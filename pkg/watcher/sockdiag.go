package watcher

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// sockDiag finds one socket by its addresses through the kernel's sock_diag
// netlink interface, in the network namespace this process runs in. It is the
// exact lookup "ss" uses: microseconds, where reading /proc/net/tcp walks the
// node's whole connection hash and formats every socket as text. It needs no
// privilege. Lookups run on the attribution worker only, so it is not safe
// for concurrent use.
type sockDiag struct {
	fd  int
	seq uint32
	buf []byte
}

const (
	sockDiagHeader  = 16 // struct nlmsghdr
	sockDiagRequest = 56 // struct inet_diag_req_v2
	sockDiagReply   = 72 // struct inet_diag_msg
	sockDiagWait    = 100 * time.Millisecond
	// inet_diag_msg offsets of the socket's owner and inode.
	sockDiagUIDAt   = 64
	sockDiagInodeAt = 68
)

func openSockDiag() (*sockDiag, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag socket: %w", err)
	}
	wait := unix.NsecToTimeval(sockDiagWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &wait); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("sock_diag timeout: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("sock_diag bind: %w", err)
	}
	return &sockDiag{fd: fd, buf: make([]byte, 8192)}, nil
}

func (d *sockDiag) close() { _ = unix.Close(d.fd) }

// errNoSocket means the kernel holds no socket for the addresses.
var errNoSocket = errors.New("no socket")

// diagSocket is the kernel's answer for one lookup.
type diagSocket struct {
	state      byte
	uid, inode uint32
}

const tcpListen = 10 // TCP_LISTEN

// find returns the inode and owner uid of the socket the kernel would deliver
// a packet from remote to local to: the connected socket, or else an
// unconnected UDP socket on the local address and port, or, on the receiving
// side (server), a TCP listener. IPv4 lookups also find dual-stack IPv6
// sockets. With no such socket, or a TCP connection already closed, the
// error is errNoSocket.
func (d *sockDiag) find(udp, server bool, local, remote netip.AddrPort) (inode, uid uint32, err error) {
	socket, err := d.query(udp, local, remote)
	if err == nil && !udp {
		switch {
		case socket.state == tcpListen && !server:
			// A client's port that a listener also uses (as after NAT) is
			// not the listener's connection.
			err = errNoSocket
		case socket.inode == 0 && server:
			// A connection not yet accepted, or closed: the server's socket
			// is its listener.
			unspecified := netip.IPv4Unspecified()
			if local.Addr().Unmap().Is6() {
				unspecified = netip.IPv6Unspecified()
			}
			socket, err = d.query(udp, local, netip.AddrPortFrom(unspecified, 0))
		}
	}
	if err == nil && socket.inode == 0 {
		err = errNoSocket
	}
	return socket.inode, socket.uid, err
}

func (d *sockDiag) query(udp bool, local, remote netip.AddrPort) (diagSocket, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	family, protocol := byte(unix.AF_INET), byte(unix.IPPROTO_TCP)
	if local.Addr().Is6() {
		family = unix.AF_INET6
		if remote.Addr().Is4() {
			remote = netip.AddrPortFrom(netip.AddrFrom16(remote.Addr().As16()), remote.Port())
		}
	} else if remote.Addr().Is6() {
		return diagSocket{}, errNoSocket // An IPv4 socket cannot talk to an IPv6 peer.
	}
	// The kernel's TCP lookup takes the socket's own address as the source;
	// its UDP lookup, for historical reasons, the peer's.
	source, destination := local, remote
	if udp {
		protocol = unix.IPPROTO_UDP
		source, destination = remote, local
	}
	d.seq++
	request := make([]byte, sockDiagHeader+sockDiagRequest)
	binary.NativeEndian.PutUint32(request[0:], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], d.seq)
	body := request[sockDiagHeader:]
	body[0], body[1] = family, protocol
	binary.NativeEndian.PutUint32(body[4:], ^uint32(0)) // Every TCP state.
	id := body[8:]                                      // struct inet_diag_sockid
	binary.BigEndian.PutUint16(id[0:], source.Port())
	binary.BigEndian.PutUint16(id[2:], destination.Port())
	copy(id[4:20], source.Addr().AsSlice())
	copy(id[20:36], destination.Addr().AsSlice())
	binary.NativeEndian.PutUint32(id[40:], ^uint32(0)) // INET_DIAG_NOCOOKIE
	binary.NativeEndian.PutUint32(id[44:], ^uint32(0))
	if err := unix.Sendto(d.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return diagSocket{}, fmt.Errorf("sock_diag send: %w", err)
	}
	for {
		n, _, err := unix.Recvfrom(d.fd, d.buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return diagSocket{}, fmt.Errorf("sock_diag receive: %w", err)
		}
		socket, done, err := d.parse(d.buf[:n])
		if done {
			return socket, err
		}
	}
}

// parse reads the replies to the current request, skipping late replies to
// earlier ones that timed out.
func (d *sockDiag) parse(data []byte) (socket diagSocket, done bool, err error) {
	for len(data) >= sockDiagHeader {
		length := int(binary.NativeEndian.Uint32(data[0:]))
		if length < sockDiagHeader || length > len(data) {
			return diagSocket{}, true, fmt.Errorf("sock_diag: malformed reply")
		}
		kind, seq := binary.NativeEndian.Uint16(data[4:]), binary.NativeEndian.Uint32(data[8:])
		message := data[sockDiagHeader:length]
		data = data[min((length+3)&^3, len(data)):]
		if seq != d.seq {
			continue
		}
		switch kind {
		case unix.NLMSG_ERROR:
			if len(message) < 4 {
				return diagSocket{}, true, fmt.Errorf("sock_diag: malformed error")
			}
			code := int32(binary.NativeEndian.Uint32(message))
			switch {
			case code == 0:
				return diagSocket{}, true, errNoSocket
			case unix.Errno(-code) == unix.ENOENT:
				return diagSocket{}, true, errNoSocket
			default:
				return diagSocket{}, true, fmt.Errorf("sock_diag: %w", os.NewSyscallError("query", unix.Errno(-code)))
			}
		case unix.SOCK_DIAG_BY_FAMILY:
			if len(message) < sockDiagReply {
				return diagSocket{}, true, fmt.Errorf("sock_diag: short reply")
			}
			return diagSocket{state: message[1], uid: binary.NativeEndian.Uint32(message[sockDiagUIDAt:]),
				inode: binary.NativeEndian.Uint32(message[sockDiagInodeAt:])}, true, nil
		}
	}
	return diagSocket{}, false, nil
}

package watcher

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func socketInode(t *testing.T, conn syscall.Conn) uint32 {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &stat) }); err != nil || statErr != nil {
		t.Fatal(err, statErr)
	}
	return uint32(stat.Ino)
}

func addrPort(t *testing.T, addr net.Addr) netip.AddrPort {
	t.Helper()
	parsed, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestSockDiagFindsSocketsByAddress(t *testing.T) {
	diag, err := openSockDiag()
	if err != nil {
		t.Skipf("sock_diag unavailable: %v", err)
	}
	defer diag.close()
	expect := func(t *testing.T, udp, server bool, local, remote netip.AddrPort, want uint32) {
		t.Helper()
		inode, uid, err := diag.find(udp, server, local, remote)
		if err != nil || inode != want || uid != uint32(os.Getuid()) {
			t.Fatalf("find(udp=%t, server=%t, %s, %s) = inode %d uid %d, %v; want inode %d uid %d", udp, server, local, remote, inode, uid, err, want, os.Getuid())
		}
	}

	for _, network := range []struct{ name, listen, dial string }{
		{"IPv4", "127.0.0.1:0", "127.0.0.1"},
		{"IPv6", "[::1]:0", "::1"},
		{"IPv4 on a dual-stack socket", "[::]:0", "127.0.0.1"},
	} {
		t.Run("TCP "+network.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", network.listen)
			if err != nil {
				t.Skipf("listen: %v", err)
			}
			defer func() { _ = listener.Close() }()
			port := listener.Addr().(*net.TCPAddr).Port
			client, err := net.Dial("tcp", net.JoinHostPort(network.dial, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			clientAddr, serverAddr := addrPort(t, client.LocalAddr()), addrPort(t, client.RemoteAddr())
			expect(t, false, false, clientAddr, serverAddr, socketInode(t, client.(*net.TCPConn)))
			expect(t, false, true, serverAddr, clientAddr, socketInode(t, server.(*net.TCPConn)))
			// A peer with no connection yet reaches the listener.
			stranger := netip.AddrPortFrom(clientAddr.Addr(), 9)
			expect(t, false, true, serverAddr, stranger, socketInode(t, listener.(*net.TCPListener)))
			// A client whose source port a listener also uses is not the
			// listener's connection.
			if inode, _, err := diag.find(false, false, serverAddr, stranger); !errors.Is(err, errNoSocket) {
				t.Fatalf("client side matched the listener: inode %d, %v", inode, err)
			}
		})
		t.Run("UDP "+network.name, func(t *testing.T) {
			bound, err := net.ListenPacket("udp", network.listen)
			if err != nil {
				t.Skipf("listen: %v", err)
			}
			defer func() { _ = bound.Close() }()
			port := bound.LocalAddr().(*net.UDPAddr).Port
			connected, err := net.Dial("udp", net.JoinHostPort(network.dial, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = connected.Close() }()
			clientAddr, serverAddr := addrPort(t, connected.LocalAddr()), addrPort(t, connected.RemoteAddr())
			expect(t, true, false, clientAddr, serverAddr, socketInode(t, connected.(*net.UDPConn)))
			expect(t, true, true, serverAddr, clientAddr, socketInode(t, bound.(*net.UDPConn)))
		})
	}

	t.Run("no socket", func(t *testing.T) {
		unused, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		local := addrPort(t, unused.LocalAddr())
		_ = unused.Close()
		remote := netip.MustParseAddrPort("127.0.0.1:9")
		for _, udp := range []bool{false, true} {
			for _, server := range []bool{false, true} {
				if _, _, err := diag.find(udp, server, local, remote); !errors.Is(err, errNoSocket) {
					t.Fatalf("find(udp=%t, server=%t) on a closed port: %v, want errNoSocket", udp, server, err)
				}
			}
		}
		if _, _, err := diag.find(false, false, local, netip.MustParseAddrPort("[2001:db8::1]:443")); !errors.Is(err, errNoSocket) {
			t.Fatalf("IPv4 socket with an IPv6 peer: %v, want errNoSocket", err)
		}
	})
}

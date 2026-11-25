package watcher

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Kernel tunnels. A VXLAN or Geneve device (Cilium's cilium_vxlan, Flannel's
// flannel.1) encapsulates traffic between nodes in UDP inside the kernel: no
// process sends or receives it. The device holds its UDP port exclusively,
// so a flow to that port on this node ends in the kernel, and one this node
// sends to another node's same port (tunnels of one cluster share it) starts
// there, from a source port the kernel derives per inner flow.

// kernelProcess is the identity recorded for an end the kernel itself owns.
var kernelProcess = processIdentity{Command: "kernel"}

// tunnelPorts lists the UDP ports of this host's kernel tunnel devices, as
// "kind device" by port, from rtnetlink (no privilege needed).
func tunnelPorts() (map[uint16]string, error) {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, fmt.Errorf("parsing links: %w", err)
	}
	ports := map[uint16]string{}
	for i := range messages {
		if messages[i].Header.Type != unix.RTM_NEWLINK {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&messages[i])
		if err != nil {
			continue
		}
		var name, kind string
		var port uint16
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.IFLA_IFNAME:
				name = string(bytes.TrimRight(attr.Value, "\x00"))
			case unix.IFLA_LINKINFO:
				kind, port = tunnelInfo(attr.Value)
			}
		}
		if port != 0 {
			ports[port] = kind + " " + name
		}
	}
	return ports, nil
}

// tunnelInfo reads a link's IFLA_LINKINFO: its kind and, for VXLAN and
// Geneve, the UDP port it receives on.
func tunnelInfo(linkInfo []byte) (kind string, port uint16) {
	var data []byte
	for _, attr := range nestedAttrs(linkInfo) {
		switch attr.kind {
		case unix.IFLA_INFO_KIND:
			kind = strings.TrimRight(string(attr.value), "\x00")
		case unix.IFLA_INFO_DATA:
			data = attr.value
		}
	}
	portAttr := map[string]uint16{"vxlan": unix.IFLA_VXLAN_PORT, "geneve": unix.IFLA_GENEVE_PORT}[kind]
	if portAttr == 0 {
		return kind, 0
	}
	for _, attr := range nestedAttrs(data) {
		if attr.kind == portAttr && len(attr.value) >= 2 {
			return kind, binary.BigEndian.Uint16(attr.value) // Network byte order.
		}
	}
	return kind, 0
}

type netlinkAttr struct {
	kind  uint16
	value []byte
}

// nestedAttrs splits a nested netlink attribute's payload.
func nestedAttrs(data []byte) []netlinkAttr {
	var attrs []netlinkAttr
	for len(data) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(data[0:]))
		kind := binary.NativeEndian.Uint16(data[2:]) &^ (unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)
		if length < unix.SizeofRtAttr || length > len(data) {
			break
		}
		attrs = append(attrs, netlinkAttr{kind, data[unix.SizeofRtAttr:length]})
		aligned := (length + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
	return attrs
}

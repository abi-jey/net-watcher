//go:build linux
// +build linux

package capture

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// DNSSniffer handles DNS packet capture and parsing using pcap (Linux optimized)
type DNSSniffer struct {
	handle     *pcap.Handle
	ifaceName  string
	ifaceIndex int
	eventChan  chan database.DNSEvent
	batchSize  int
	debug      bool
}

// NewDNSSniffer creates a new DNS sniffer for specified interface
func NewDNSSniffer(iface string, batchSize int, debug bool) (*DNSSniffer, error) {
	// Get interface by name
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", iface, err)
	}

	// Open handle for packet capture
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
	}

	// Set BPF filter to capture only DNS traffic (port 53)
	bpfFilter := "udp and port 53"
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	sniffer := &DNSSniffer{
		handle:     handle,
		ifaceName:  iface,
		ifaceIndex: ifaceObj.Index,
		eventChan:  make(chan database.DNSEvent, 1000),
		batchSize:  batchSize,
		debug:      debug,
	}

	return sniffer, nil
}

// Start begins packet capture
func (d *DNSSniffer) Start() error {
	if d.debug {
		fmt.Printf("Starting DNS capture on interface %s (Linux optimized)\n", d.ifaceName)
	}

	// Start packet processing in a goroutine
	go d.processPackets()

	return nil
}

// Stop stops packet capture
func (d *DNSSniffer) Stop() {
	if d.handle != nil {
		d.handle.Close()
	}
	close(d.eventChan)
}

// GetEventChannel returns channel for DNS events
func (d *DNSSniffer) GetEventChannel() <-chan database.DNSEvent {
	return d.eventChan
}

// processPackets captures and processes packets
func (d *DNSSniffer) processPackets() {
	packetSource := gopacket.NewPacketSource(d.handle, d.handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		event, err := d.parsePacket(packet)
		if err != nil {
			if d.debug {
				fmt.Printf("Failed to parse packet: %v\n", err)
			}
			continue
		}

		if event != nil {
			select {
			case d.eventChan <- *event:
			default:
				if d.debug {
					fmt.Println("Event channel full, dropping packet")
				}
			}
		}
	}
}

// parsePacket extracts DNS information from a packet
func (d *DNSSniffer) parsePacket(packet gopacket.Packet) (*database.DNSEvent, error) {
	// Extract layers
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		if ipLayer == nil {
			return nil, fmt.Errorf("no IP layer found")
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, fmt.Errorf("no UDP layer found")
	}

	// Check if it's DNS traffic (port 53)
	udp, ok := udpLayer.(*layers.UDP)
	if !ok || udp.DstPort != 53 {
		return nil, fmt.Errorf("not a DNS packet")
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, fmt.Errorf("no DNS layer found")
	}

	// Extract IP information
	var srcIP, dstIP string
	var packetSize int = len(packet.Data())

	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	case *layers.IPv6:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	default:
		return nil, fmt.Errorf("unknown IP layer type")
	}

	// Extract DNS information
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil, fmt.Errorf("failed to decode DNS layer")
	}

	// Process DNS questions
	for _, question := range dns.Questions {
		// Only process standard queries
		if dns.QR == false { // QR=false means it's a query
			event := database.DNSEvent{
				Timestamp:  time.Now(),
				SourceIP:   srcIP,
				DestIP:     dstIP,
				DomainName: string(question.Name),
				RecordType: dnsTypeToString(question.Type),
				Interface:  d.ifaceName,
				PacketSize: packetSize,
			}

			if d.debug {
				fmt.Printf("DNS Query: %s (%s) from %s to %s\n",
					event.DomainName, event.RecordType, event.SourceIP, event.DestIP)
			}

			return &event, nil
		}
	}

	return nil, nil
}

// dnsTypeToString converts DNS type to string representation
func dnsTypeToString(dnsType layers.DNSType) string {
	switch dnsType {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE_%d", uint16(dnsType))
	}
}

// GetEgressInterfaces returns list of interfaces that can be used for egress traffic
func GetEgressInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var egressInterfaces []string

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip interfaces without IP addresses
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		// Check if interface has a non-local IP address
		hasEgressIP := false
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Skip localhost and link-local addresses
			if ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}

			// Check if it's a routable IP
			if !ipNet.IP.IsPrivate() || ipNet.IP.IsGlobalUnicast() {
				hasEgressIP = true
				break
			}
		}

		if hasEgressIP {
			// Filter out common non-egress interfaces
			if !isNonEgressInterface(iface.Name) {
				egressInterfaces = append(egressInterfaces, iface.Name)
			}
		}
	}

	return egressInterfaces, nil
}

// isNonEgressInterface checks if interface name suggests it's not for egress
func isNonEgressInterface(name string) bool {
	nonEgressPatterns := []string{
		"docker", "virbr", "veth", "br-", "kube", "flannel",
		"cni", "tun", "tap", "vbox", "utun", "awdl",
	}

	lowerName := strings.ToLower(name)
	for _, pattern := range nonEgressPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// ValidateInterface checks if an interface exists and is up
func ValidateInterface(ifaceName string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			if iface.Flags&net.FlagUp == 0 {
				return fmt.Errorf("interface %s is down", ifaceName)
			}
			return nil
		}
	}

	return fmt.Errorf("interface %s not found", ifaceName)
}

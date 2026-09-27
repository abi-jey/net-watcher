package watcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// Watcher orchestrates multiple sniffers and the database writer
type Watcher struct {
	dbPath         string
	interfaces     []net.Interface
	logger         *log.Logger
	sessionManager *SessionManager
	db             *database.DB
	Discover       func() ([]net.Interface, error)
}

// SetContextLookup installs optional inventory enrichment before capture starts.
func (w *Watcher) SetContextLookup(lookup func(string, uint16, string) string) {
	w.sessionManager.contextLookup = lookup
}

// New creates a new Watcher instance
// onlyFilter is a comma-separated list of protocols to log (tcp,udp,icmp,dns,tls)
// excludeFilter is a comma-separated list of traffic to exclude (multicast,broadcast,linklocal,bittorrent)
// excludePorts is a comma-separated list of ports to exclude
func New(dbPath string, ifaces []net.Interface, logger *log.Logger, onlyFilter, excludeFilter, excludePorts string) (*Watcher, error) {
	// Initialize database
	db, err := database.New(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return &Watcher{
		dbPath:         dbPath,
		interfaces:     ifaces,
		logger:         logger,
		sessionManager: NewSessionManager(logger, db, onlyFilter, excludeFilter, excludePorts),
		db:             db,
	}, nil
}

// NewWithDB creates a Watcher with an existing database connection
func NewWithDB(db *database.DB, ifaces []net.Interface, logger *log.Logger, onlyFilter, excludeFilter, excludePorts string) (*Watcher, error) {
	return &Watcher{
		dbPath:         "",
		interfaces:     ifaces,
		logger:         logger,
		sessionManager: NewSessionManager(logger, db, onlyFilter, excludeFilter, excludePorts),
		db:             nil, // DB managed externally, don't close it
	}, nil
}

// Run starts the monitoring process. It blocks until the context is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	active := make(map[int]context.CancelFunc)
	finished := make(chan int, 1024)
	update := func(interfaces []net.Interface) {
		present := make(map[int]bool)
		for _, iface := range interfaces {
			present[iface.Index] = true
			if _, exists := active[iface.Index]; exists {
				continue
			}
			captureCtx, cancel := context.WithCancel(ctx)
			active[iface.Index] = cancel
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := w.sniffInterface(captureCtx, iface); err != nil && captureCtx.Err() == nil {
					w.logger.Error("Sniffer error", "interface", iface.Name, "error", err)
				}
				select {
				case finished <- iface.Index:
				case <-ctx.Done():
				}
			}()
		}
		for index, cancel := range active {
			if !present[index] {
				cancel()
			}
		}
	}
	update(w.interfaces)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
capture:
	for {
		select {
		case <-ctx.Done():
			break capture
		case index := <-finished:
			if cancel, exists := active[index]; exists {
				cancel()
				delete(active, index)
			}
		case <-ticker.C:
			if w.Discover != nil {
				interfaces, err := w.Discover()
				if err != nil {
					w.logger.Error("Interface discovery failed", "error", err)
				} else {
					update(interfaces)
				}
			}
		}
	}
	for _, cancel := range active {
		cancel()
	}
	wg.Wait()
	w.sessionManager.Stop()
	if w.db != nil {
		w.db.Close()
	}

	return nil
}

// sniffInterface is the core logic that uses afpacket
func (w *Watcher) sniffInterface(ctx context.Context, iface net.Interface) error {
	log.Info("Opening raw socket", "interface", iface.Name)

	// 1. Open AF_PACKET handle (Linux specific high-performance capture)
	// A Ring Buffer Clone of interface is created by kernel
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface.Name),
		afpacket.OptFrameSize(4096),
		afpacket.OptBlockSize(4096*16),
		afpacket.OptNumBlocks(8),
		afpacket.OptPollTimeout(500*time.Millisecond),
	)
	if err != nil {
		return fmt.Errorf("failed to create afpacket: %w", err)
	}
	defer handle.Close()

	// 2. Create the packet source from the handle
	// This turns raw bytes into readable packets
	var decoder gopacket.Decoder = layers.LinkTypeEthernet
	if len(iface.HardwareAddr) == 0 {
		decoder = layers.LinkTypeRaw
	}
	source := gopacket.NewPacketSource(handle, decoder)

	// 3. Start packet drop monitoring goroutine
	go w.monitorDrops(ctx, handle, iface.Name)

	// 4. Process packets loop
	w.logger.Info("Capture running...", "interface", iface.Name)

	for ctx.Err() == nil {
		// Packets() starts a reader goroutine which may access the mmap after
		// handle.Close when a discovered interface disappears.
		packet, err := source.NextPacket()
		if errors.Is(err, afpacket.ErrTimeout) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read packet from %s: %w", iface.Name, err)
		}
		w.processPacket(packet, iface.Name)
	}
	return nil
}

// monitorDrops periodically checks for packet drops and logs warnings
func (w *Watcher) monitorDrops(ctx context.Context, handle *afpacket.TPacket, ifaceName string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lastDrops, lastTotal uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, stats, err := handle.SocketStats()
			if err != nil {
				w.logger.Error("Failed to get socket stats", "interface", ifaceName, "error", err)
				continue
			}

			drops := uint64(stats.Drops())
			total := uint64(stats.Packets())

			// Calculate drops since last check
			newDrops := drops - lastDrops
			newPackets := total - lastTotal

			if newDrops > 0 {
				dropRate := float64(0)
				if newPackets > 0 {
					dropRate = float64(newDrops) / float64(newPackets+newDrops) * 100
				}
				w.logger.Warn("[SNIFFER DROPS]",
					"interface", ifaceName,
					"drops", newDrops,
					"total_drops", drops,
					"drop_rate", fmt.Sprintf("%.2f%%", dropRate),
				)
			}
			w.logger.Info("[SNIFFER STATS]",
				"timeframe", "30s",
				"interface", ifaceName,
				"total_packets", total,
				"total_drops", drops,
			)

			lastDrops = drops
			lastTotal = total
		}
	}
}

// processPacket handles a single captured packet
func (w *Watcher) processPacket(packet gopacket.Packet, ifaceName string) {
	// Check for packet decoding errors
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		// Get full hex dump for debugging
		data := packet.Data()
		hexDump := ""
		for i := 0; i < len(data); i++ {
			if i > 0 && i%16 == 0 {
				hexDump += " "
			}
			hexDump += fmt.Sprintf("%02x", data[i])
		}

		w.logger.Debug("[PACKET ERROR]",
			"interface", ifaceName,
			"error", errLayer.Error(),
			"len", len(data),
			"hex", hexDump,
		)
		return
	}

	var srcIP, dstIP net.IP
	var isIPv6 bool

	// Try IPv4 first
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
		isIPv6 = false
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		// Try IPv6
		ip6, _ := ip6Layer.(*layers.IPv6)
		srcIP = ip6.SrcIP
		dstIP = ip6.DstIP
		isIPv6 = true
	} else {
		// Neither IPv4 nor IPv6
		return
	}

	// Check for TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		src := fmt.Sprintf("[%s]:%d", srcIP, tcp.SrcPort)
		dst := fmt.Sprintf("[%s]:%d", dstIP, tcp.DstPort)
		length := len(packet.Data())

		// Track TCP connection lifecycle
		w.sessionManager.TrackTCP(ifaceName, src, dst, tcp.SYN && !tcp.ACK, tcp.FIN, tcp.RST, length, isIPv6)
		if tcp.SrcPort == 53 || tcp.DstPort == 53 {
			w.sessionManager.TrackDNSTCP(ifaceName, src, dst, tcp, packet.Metadata().Timestamp, isIPv6)
		}

		// Check for TLS handshake (port 443 or has payload starting with 0x16)
		if len(tcp.Payload) > 0 && tcp.Payload[0] == 0x16 {
			if sni := ParseTLSSNI(tcp.Payload); sni != "" {
				w.sessionManager.TrackTLSHandshake(ifaceName, src, dst, sni, isIPv6)
			}
		}
		return
	}

	// Check for UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		src := fmt.Sprintf("[%s]:%d", srcIP, udp.SrcPort)
		dst := fmt.Sprintf("[%s]:%d", dstIP, udp.DstPort)
		length := len(packet.Data())

		// Track UDP "connection"
		w.sessionManager.TrackUDP(ifaceName, src, dst, uint16(udp.SrcPort), uint16(udp.DstPort), length, isIPv6)

		// Check for DNS (port 53)
		if udp.SrcPort == 53 || udp.DstPort == 53 {
			w.sessionManager.TrackDNSPacket(ifaceName, src, dst, "UDP", udp.Payload, packet.Metadata().Timestamp, isIPv6)
		}
		return
	}

	// Check for ICMPv4
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		src := srcIP.String()
		dst := dstIP.String()
		length := len(packet.Data())

		w.sessionManager.TrackICMP(ifaceName, src, dst, uint8(icmp.TypeCode.Type()), uint8(icmp.TypeCode.Code()), length, false, icmp.Payload)
		return
	}

	// Check for ICMPv6
	if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6, _ := icmp6Layer.(*layers.ICMPv6)
		src := srcIP.String()
		dst := dstIP.String()
		length := len(packet.Data())

		w.sessionManager.TrackICMP(ifaceName, src, dst, uint8(icmp6.TypeCode.Type()), uint8(icmp6.TypeCode.Code()), length, true, icmp6.Payload)
		return
	}
}

package ingest

import (
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// A collector labels its own node's interface addresses, but another node's
// temporary public IPv6 or public address is unknown to it: its events show
// that node as an internet address. Collectors therefore report their global
// addresses with their health, the ingester keeps when each node held each
// address (node_addresses), and an event side no collector attributed is
// labelled with the one node that held its address at capture time.
//
// Only global addresses are reported: public and tailnet addresses identify
// one host, while private and link-local ones repeat across hosts and sites
// (every Docker host has 172.17.0.1), and Kubernetes already lists a node's
// internal addresses.
const (
	// acceptsHeader on a successful response lists the optional Health
	// fields this ingester stores. Collectors send them only after seeing it,
	// so an older ingester, which rejects unknown fields, is never sent one.
	acceptsHeader    = "X-Net-Watcher-Accepts"
	acceptsAddresses = "addresses"
	// acceptsPeerProcesses: events may carry the PeerProcess* fields.
	acceptsPeerProcesses = "peer-process"
	// acceptsProbes: events may carry the Probe field.
	acceptsProbes = "probe"
	// acceptsFlows: events may carry FlowID and the flow totals (SrcBytes,
	// DstBytes, SrcPackets, DstPackets).
	acceptsFlows = "flows"

	maxReportedAddresses = 256
	// An address is credited to its node from addressBefore its first report
	// (it was assigned before the report that listed it) until addressAfter
	// its last one.
	addressBefore = time.Hour
	addressAfter  = 10 * time.Minute
	// addressPersistEvery bounds how often a known address's LastSeen is
	// written; memory always has the latest report.
	addressPersistEvery = 5 * time.Minute
)

// reportable reports whether an interface address identifies its host.
func reportable(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsGlobalUnicast() && !address.IsPrivate()
}

// reportableAddresses keeps the addresses worth reporting, once each.
func reportableAddresses(all []string) []string {
	seen := map[netip.Addr]bool{}
	var list []string
	for _, value := range all {
		address, err := netip.ParseAddr(value)
		if err != nil || !reportable(address) || seen[address.Unmap()] {
			continue
		}
		seen[address.Unmap()] = true
		list = append(list, address.Unmap().String())
		if len(list) == maxReportedAddresses {
			break
		}
	}
	return list
}

type nodeAddresses struct {
	mu     sync.Mutex
	loaded bool
	claims map[string][]database.NodeAddress // By address.
}

func (n *nodeAddresses) load(tx *gorm.DB) error {
	if n.loaded {
		return nil
	}
	var rows []database.NodeAddress
	if err := tx.Find(&rows).Error; err != nil {
		return err
	}
	n.claims = map[string][]database.NodeAddress{}
	for _, row := range rows {
		n.claims[row.Address] = append(n.claims[row.Address], row)
	}
	n.loaded = true
	return nil
}

// record notes the addresses node reported at at, writing new addresses and
// stale LastSeen times through tx.
func (n *nodeAddresses) record(tx *gorm.DB, node string, addresses []string, at time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.load(tx); err != nil {
		return err
	}
	var writes []database.NodeAddress
	for _, address := range reportableAddresses(addresses) {
		claims := n.claims[address]
		index := -1
		for i := range claims {
			if claims[i].Node == node {
				index = i
			}
		}
		if index < 0 {
			claim := database.NodeAddress{Node: node, Address: address, FirstSeen: at, LastSeen: at}
			n.claims[address] = append(claims, claim)
			writes = append(writes, claim)
			continue
		}
		claim := &claims[index]
		if at.Before(claim.FirstSeen) {
			claim.FirstSeen = at // A queued older report.
			writes = append(writes, *claim)
		}
		if at.After(claim.LastSeen) {
			persisted := at.Sub(claim.LastSeen) >= addressPersistEvery
			claim.LastSeen = at
			if persisted {
				writes = append(writes, *claim)
			}
		}
	}
	if len(writes) == 0 {
		return nil
	}
	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "node"}, {Name: "address"}},
		DoUpdates: clause.Set{
			{Column: clause.Column{Name: "first_seen"}, Value: gorm.Expr("min(node_addresses.first_seen, excluded.first_seen)")},
			{Column: clause.Column{Name: "last_seen"}, Value: gorm.Expr("max(node_addresses.last_seen, excluded.last_seen)")},
		},
	}).Create(&writes).Error
}

// owner returns the one node that held address at at.
func (n *nodeAddresses) owner(address string, at time.Time) (database.NodeAddress, bool) {
	parsed, err := netip.ParseAddr(address)
	if err != nil || !reportable(parsed) {
		return database.NodeAddress{}, false
	}
	var found database.NodeAddress
	matches := 0
	for _, claim := range n.claims[parsed.Unmap().String()] {
		if !at.Before(claim.FirstSeen.Add(-addressBefore)) && !at.After(claim.LastSeen.Add(addressAfter)) {
			found = claim
			matches++
		}
	}
	return found, matches == 1
}

// label attributes the event sides no collector attributed whose address a
// node held at capture time.
func (n *nodeAddresses) label(tx *gorm.DB, events []database.NetworkEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.load(tx); err != nil {
		return err
	}
	if len(n.claims) == 0 {
		return nil
	}
	for i := range events {
		event := &events[i]
		for _, side := range []struct {
			ip                              string
			kind, name, confidence, context *string
		}{
			{event.SrcIP, &event.SrcKind, &event.SrcName, &event.SrcAttribution, &event.SourceContext},
			{event.DstIP, &event.DstKind, &event.DstName, &event.DstAttribution, &event.DestinationContext},
		} {
			if side.ip == "" || *side.kind != "" {
				continue
			}
			claim, ok := n.owner(side.ip, event.Timestamp)
			if !ok {
				continue
			}
			*side.kind, *side.name, *side.confidence = "node", claim.Node, "node"
			if *side.context == "" {
				// The context shape of a node the collector attributed
				// itself, with the evidence for this one.
				evidence, _ := json.Marshal(struct {
					Kind, Name, Node, Confidence string
					ObservedAt                   time.Time
					Evidence                     string
				}{"node", claim.Node, claim.Node, "node", claim.LastSeen, "interface address reported by the node's collector"})
				*side.context = string(evidence)
			}
		}
	}
	return nil
}

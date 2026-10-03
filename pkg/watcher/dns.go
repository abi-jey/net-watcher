package watcher

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const dnsWindow = 30 * time.Second
const maxDNSState = 16384
const dnsPruneInterval = time.Second

// DNSRecord retains answer ownership as well as its value: unrelated answers cannot
// establish a binding for the question's name.
type DNSRecord struct {
	Name  string
	Type  string
	Value string
	TTL   uint32
}

type dnsKey struct {
	Client, Resolver, Name, Transport string
	ID                                uint16
	Type                              layers.DNSType
	Class                             layers.DNSClass
}

type dnsStream struct {
	Next   uint32
	Buffer []byte
	Seen   time.Time
}

type dnsQuery struct {
	At            time.Time
	ClientContext string
}

func contextIdentity(raw string) string {
	var value struct{ UID string }
	_ = json.Unmarshal([]byte(raw), &value)
	return value.UID
}

type dnsTracker struct {
	lastPrune time.Time
	mu        sync.Mutex
	pending   map[dnsKey]dnsQuery
	bindings  map[string][]database.DNSResolution
	streams   map[string]*dnsStream
}

func newDNSTracker() *dnsTracker {
	return &dnsTracker{pending: make(map[dnsKey]dnsQuery), bindings: make(map[string][]database.DNSResolution), streams: make(map[string]*dnsStream)}
}

func (d *dnsTracker) restore(db *database.DB) error {
	var rows []database.DNSResolution
	if err := db.Where("expires_at > ?", time.Now()).Order("response_time DESC").Limit(maxDNSState).Find(&rows).Error; err != nil {
		return err
	}
	for index := len(rows) - 1; index >= 0; index-- {
		row := rows[index]
		key := row.ClientIP + "\x00" + row.IP
		entries := d.bindings[key]
		if len(entries) >= 32 {
			entries = entries[len(entries)-31:]
		}
		d.bindings[key] = append(entries, row)
	}
	return nil
}

func dnsName(name []byte) string { return strings.ToLower(strings.TrimSuffix(string(name), ".")) }

func (d *dnsTracker) prune(now time.Time) {
	// Packet handlers still check individual entries; global eviction need not
	// walk all shared state on every packet. Callers hold d.mu.
	if !d.lastPrune.IsZero() && now.Sub(d.lastPrune) < dnsPruneInterval {
		return
	}
	d.lastPrune = now
	for key, query := range d.pending {
		if now.Sub(query.At) > dnsWindow {
			delete(d.pending, key)
		}
	}
	for key, entries := range d.bindings {
		live := entries[:0]
		for _, entry := range entries {
			if now.Before(entry.ExpiresAt) {
				live = append(live, entry)
			}
		}
		if len(live) == 0 {
			delete(d.bindings, key)
		} else {
			d.bindings[key] = live
		}
	}
	for key, stream := range d.streams {
		if now.Sub(stream.Seen) > dnsWindow {
			delete(d.streams, key)
		}
	}
}

func (d *dnsTracker) lookup(client, ip string, at time.Time) []database.DNSResolution {
	d.mu.Lock()
	defer d.mu.Unlock()
	var matches []database.DNSResolution
	for _, entry := range d.bindings[client+"\x00"+ip] {
		if !at.Before(entry.ResponseTime) && at.Before(entry.ExpiresAt) {
			matches = append(matches, entry)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ResponseTime.Before(matches[j].ResponseTime) })
	return matches
}

// TrackDNSPacket accepts a complete DNS message, preserving failed and unmatched
// responses as observations but creating bindings only for matched successful answers.
func (sm *SessionManager) TrackDNSPacket(iface, src, dst, transport string, payload []byte, at time.Time, ipv6 bool) {
	if !sm.shouldLog("dns") {
		return
	}
	var message layers.DNS
	if err := message.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil || message.OpCode != layers.DNSOpCodeQuery {
		return
	}
	client, resolver := src, dst
	if message.QR {
		client, resolver = dst, src
	}
	clientIP, clientPort := parseAddr(client)
	resolverIP, resolverPort := parseAddr(resolver)
	if resolverPort != 53 {
		return
	}
	sourceIP, sourcePort := parseAddr(src)
	destinationIP, destinationPort := parseAddr(dst)
	if sm.shouldExclude(src, dst, sourcePort, destinationPort) {
		return
	}
	version := uint8(4)
	if ipv6 {
		version = 6
	}
	records := make([]DNSRecord, 0, len(message.Answers))
	for _, answer := range message.Answers {
		if answer.Class != layers.DNSClassIN {
			continue
		}
		record := DNSRecord{Name: dnsName(answer.Name), Type: answer.Type.String(), TTL: answer.TTL}
		switch answer.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if answer.IP == nil {
				continue
			}
			record.Value = answer.IP.String()
		case layers.DNSTypeCNAME:
			record.Value = dnsName(answer.CNAME)
		default:
			continue
		}
		records = append(records, record)
	}
	recordJSON, _ := json.Marshal(records)
	d := sm.dns
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prune(at)
	for _, question := range message.Questions {
		name := dnsName(question.Name)
		key := dnsKey{client, resolver, name, transport, message.ID, question.Type, question.Class}
		event := database.NetworkEvent{Timestamp: at, EventType: database.EventDNS, Interface: iface, IPVersion: version,
			SrcIP: sourceIP, SrcPort: sourcePort, DstIP: destinationIP, DstPort: destinationPort,
			DNSVersion: 1, DNSID: message.ID, DNSQuery: name, DNSQuestionType: question.Type.String(), Protocol: transport,
			DNSType: "QUERY", DNSRecords: string(recordJSON)}
		if !message.QR {
			if old, exists := d.pending[key]; exists && at.Sub(old.At) > dnsWindow {
				delete(d.pending, key)
			}
			if len(d.pending) < maxDNSState {
				if _, exists := d.pending[key]; !exists {
					query := dnsQuery{At: at}
					if sm.contextLookup != nil {
						query.ClientContext = sm.contextLookup(clientIP, clientPort, transport)
					}
					d.pending[key] = query
				}
			}
			sm.queueEvent(event)
			continue
		}
		event.DNSType = "RESPONSE"
		event.DNSTruncated = message.TC
		event.DNSResponseCode = message.ResponseCode.String()
		query, matched := d.pending[key]
		queryTime := query.At
		delete(d.pending, key)
		event.DNSMatched = matched && !at.Before(queryTime) && at.Sub(queryTime) <= dnsWindow
		if sm.contextLookup != nil && contextIdentity(query.ClientContext) != contextIdentity(sm.contextLookup(clientIP, clientPort, transport)) {
			event.DNSMatched = false
		}
		if event.DNSMatched {
			event.DNSQueryTime = queryTime
		}
		var ips, cnames []string
		for _, r := range records {
			if r.Type == "CNAME" {
				cnames = append(cnames, r.Value)
			} else {
				ips = append(ips, r.Value)
			}
		}
		event.DNSAnswers, event.DNSCNAMEs = strings.Join(ips, ","), strings.Join(cnames, ",")
		if event.DNSMatched && !message.TC && message.ResponseCode == layers.DNSResponseCodeNoErr && question.Class == layers.DNSClassIN {
			resolutions := resolveAnswers(name, question.Type.String(), records)
			for i := range resolutions {
				r := &resolutions[i]
				r.QueryTime, r.ResponseTime, r.Interface, r.Transport = queryTime, at, iface, transport
				r.ExpiresAt = at.Add(time.Duration(r.TTL) * time.Second)
				r.TransactionID, r.ClientIP, r.ClientPort = message.ID, clientIP, clientPort
				r.ResolverIP, r.ResolverPort, r.AnswerRecords = resolverIP, resolverPort, string(recordJSON)
				r.ClientContext = query.ClientContext
				if sm.contextLookup != nil {
					r.AddressContext = sm.contextLookup(r.IP, 0, "")
				}
			}
			// Persist evidence before making it available to subsequent connections.
			if len(resolutions) > 0 && sm.db != nil {
				if err := sm.db.Create(&resolutions).Error; err != nil {
					sm.logger.Error("Failed to persist DNS evidence", "error", err)
				} else {
					ids := make([]uint, 0, len(resolutions))
					for _, r := range resolutions {
						ids = append(ids, r.ID)
						cacheKey := clientIP + "\x00" + r.IP
						_, exists := d.bindings[cacheKey]
						if r.TTL > 0 && (exists || len(d.bindings) < maxDNSState) {
							entries := d.bindings[cacheKey]
							if len(entries) >= 32 {
								entries = entries[len(entries)-31:]
							}
							d.bindings[cacheKey] = append(entries, r)
						}
					}
					encoded, _ := json.Marshal(ids)
					event.DNSResolutionIDs = string(encoded)
				}
			}
		}
		sm.queueEvent(event)
	}
}

// resolveAnswers follows only answer-owner CNAME chains rooted at the question.
// The weakest TTL in the chain bounds the lifetime of the resulting mapping.
func resolveAnswers(name, queryType string, records []DNSRecord) []database.DNSResolution {
	if queryType != "A" && queryType != "AAAA" {
		return nil
	}
	current, ttl := name, ^uint32(0)
	var chain []DNSRecord
	seen := map[string]bool{}
	complete := false
	for range 32 {
		if seen[current] {
			return nil
		}
		seen[current] = true
		var aliases []DNSRecord
		for _, r := range records {
			if r.Name == current && r.Type == "CNAME" {
				aliases = append(aliases, r)
			}
		}
		if len(aliases) == 0 {
			complete = true
			break
		}
		for _, r := range aliases {
			if r.Value != aliases[0].Value {
				return nil
			}
			ttl = min(ttl, r.TTL)
		}
		chain = append(chain, aliases[0])
		current = aliases[0].Value
	}
	if !complete {
		return nil
	}
	encoded, _ := json.Marshal(chain)
	var result []database.DNSResolution
	addresses := map[string]int{}
	for _, r := range records {
		if r.Name != current || r.Type != queryType || net.ParseIP(r.Value) == nil {
			continue
		}
		if index, exists := addresses[r.Value]; exists {
			result[index].TTL = min(result[index].TTL, r.TTL)
			continue
		}
		addresses[r.Value] = len(result)
		result = append(result, database.DNSResolution{Name: name, QueryType: queryType, IP: r.Value, TTL: min(ttl, r.TTL), CNAMEChain: string(encoded)})
	}
	return result
}

// TrackDNSTCP reconstructs length-prefixed DNS messages on observed TCP streams.
// A missing SYN or sequence gap invalidates that direction rather than guessing
// message boundaries. Retransmissions and messages split across packets are handled.
func (sm *SessionManager) TrackDNSTCP(iface, src, dst string, tcp *layers.TCP, at time.Time, ipv6 bool) {
	key := fmt.Sprintf("%s/%s/%s", iface, src, dst)
	d := sm.dns
	d.mu.Lock()
	d.prune(at)
	stream := d.streams[key]
	if stream != nil && at.Sub(stream.Seen) > dnsWindow {
		delete(d.streams, key)
		stream = nil
	}
	if tcp.SYN && (stream != nil || len(d.streams) < maxDNSState) {
		d.streams[key] = &dnsStream{Next: tcp.Seq + 1, Seen: at}
	}
	stream = d.streams[key]
	var messages [][]byte
	if stream != nil && len(tcp.Payload) > 0 {
		seq := tcp.Seq
		if tcp.SYN {
			seq++
		}
		delta := int32(seq - stream.Next)
		payload := tcp.Payload
		if delta > 0 {
			delete(d.streams, key)
		} else {
			skip := min(int64(-int64(delta)), int64(len(payload)))
			payload = payload[skip:]
			stream.Next += uint32(len(payload))
			stream.Seen = at
			stream.Buffer = append(stream.Buffer, payload...)
			for len(stream.Buffer) >= 2 {
				length := int(binary.BigEndian.Uint16(stream.Buffer))
				if length < 12 {
					delete(d.streams, key)
					break
				}
				if len(stream.Buffer) < length+2 {
					break
				}
				messages = append(messages, append([]byte(nil), stream.Buffer[2:length+2]...))
				stream.Buffer = stream.Buffer[length+2:]
			}
			if len(stream.Buffer) > 65537 {
				delete(d.streams, key)
			}
		}
	}
	if tcp.FIN || tcp.RST {
		delete(d.streams, key)
	}
	d.mu.Unlock()
	for _, payload := range messages {
		sm.TrackDNSPacket(iface, src, dst, "TCP", payload, at, ipv6)
	}
}

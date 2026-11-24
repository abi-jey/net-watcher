package database

import (
	"net/netip"
	"sync"
)

// prefixes caches parsed prefixes: a filter compares every row it reads
// against the same few.
var prefixes sync.Map

// IPInPrefix reports whether an address lies in a prefix such as
// 10.0.0.0/8; it is the SQL function ip_in_prefix(ip, prefix). An IPv4
// address written as IPv6 (::ffff:10.0.0.1) counts as IPv4.
func IPInPrefix(ip, prefix string) bool {
	parsed, ok := prefixes.Load(prefix)
	if !ok {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return false
		}
		parsed, _ = prefixes.LoadOrStore(prefix, p.Masked())
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return parsed.(netip.Prefix).Contains(addr.Unmap())
}

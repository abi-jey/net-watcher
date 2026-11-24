package web

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/abja/net-watcher/internal/database"
	"github.com/google/gopacket/layers"
)

// Event filter expressions select events by any mix of conditions:
//
//	src.kind != pod and (dst.kind = node or port = 53) and not ns = kube-system
//
// Grammar (keywords are case-insensitive):
//
//	expr    = or
//	or      = and { "or" and }
//	and     = unary { ["and"] unary }        adjacent terms are joined by and
//	unary   = ("not" | "!") unary | "(" expr ")" | compare | text
//	compare = field op ( value | "(" value { "," value } ")" )
//	op      = "=" | "!=" | "~" | "!~" | "<" | "<=" | ">" | ">="
//
// A value is a bare word or a "quoted string" (\" and \\ escape). A word
// that no operator follows searches text, like the search box; a leading "-"
// negates a word or a comparison ("-coredns", "-ns=kube-system"). A list
// matches any of its values. "=" is exact, "~" contains (ASCII letters in
// any case); "none" matches an unset value.
//
// A field without src./dst. covers both ends of a connection: "=" matches
// when either end matches and "!=" when neither does, so "kind != pod" keeps
// only events with no pod at either end.
//
// The server compiles an expression to SQL for searches and evaluates it in
// Go for the live tail; the two must agree (filter_test.go checks).
// web/src/lib/filter.ts parses the same language for the page.

const (
	maxFilterLength = 4000
	maxFilterTerms  = 100
	maxFilterValues = 100
)

type exprKind int

const (
	exprAnd exprKind = iota
	exprOr
	exprNot
	exprCompare
	exprText
)

// expr is a parsed filter expression.
type expr struct {
	kind  exprKind
	terms []*expr // and, or
	inner *expr   // not

	// compare and text
	field *filterField
	name  string   // canonical field name
	op    string   // compare operator
	raw   []string // values as written
	norm  []value  // values as compared
}

// value is one normalized comparison value.
type value struct {
	text   string       // strings, enums, exact addresses, domains, contains
	prefix netip.Prefix // address prefixes
	lo, hi int64        // numbers and number ranges
	role   string       // interface types
}

type fieldKind int

const (
	stringField fieldKind = iota // exact or contains; "none" is empty
	enumField                    // a fixed set of values
	ipField                      // address or prefix; contains
	numberField                  // number or range; comparisons
	domainField                  // name or subdomain, any case; contains
	roleField                    // interface type
)

type filterField struct {
	kind    fieldKind
	columns []string
	// entity: the columns describe one thing (a domain in three columns, a
	// peer's address and name), so "none" means all are unset. Otherwise
	// they are the two ends of a connection.
	entity bool
	values map[string]string // enumField: accepted input (lower case) -> stored
	shown  []string          // enumField: the values errors suggest, when not all of values
	unit   func(string) (int64, error)
}

var endpointKinds = map[string]string{"pod": "pod", "node": "node", "service": "service", "endpoint": "endpoint", "none": "", "external": ""}

var routeValues = map[string]string{"exit-node": "exit-node", "subnet-router": "subnet-router", "via-tailnet": "via-tailnet", "none": ""}

var sideValues = map[string]string{"src": "src", "dst": "dst", "none": ""}

// rcodeNames are the standard names of DNS response codes. The collector
// stores gopacket's descriptions instead ("Non-Existent Domain", and "Server
// Failure " with a trailing space), so filters accept either and compare the
// stored text.
var rcodeNames = map[string]layers.DNSResponseCode{
	"noerror": layers.DNSResponseCodeNoErr, "formerr": layers.DNSResponseCodeFormErr, "servfail": layers.DNSResponseCodeServFail,
	"nxdomain": layers.DNSResponseCodeNXDomain, "notimp": layers.DNSResponseCodeNotImp, "refused": layers.DNSResponseCodeRefused,
	"yxdomain": layers.DNSResponseCodeYXDomain, "yxrrset": layers.DNSResponseCodeYXRRSet, "nxrrset": layers.DNSResponseCodeNXRRSet,
	"notauth": layers.DNSResponseCodeNotAuth, "notzone": layers.DNSResponseCodeNotZone, "badvers": layers.DNSResponseCodeBadVers,
	"none": 0,
}

var rcodeValues = func() map[string]string {
	values := map[string]string{}
	for name, code := range rcodeNames {
		if name == "none" {
			values[name] = ""
			continue
		}
		values[name] = code.String()
		values[strings.ToLower(strings.TrimSpace(code.String()))] = code.String()
	}
	return values
}()

var eventTypeValues = func() map[string]string {
	values := map[string]string{}
	for _, t := range []database.EventType{database.EventTCPStart, database.EventTCPEnd, database.EventUDPStart, database.EventUDPEnd, database.EventDNS,
		database.EventTLSSNI, database.EventICMP, database.EventTimeout, database.EventGap, database.EventTCP, database.EventUDP, database.EventHourlySummary} {
		values[strings.ToLower(string(t))] = string(t)
	}
	return values
}()

func sided(kind fieldKind, column string, values map[string]string, unit func(string) (int64, error)) (both, src, dst *filterField) {
	return &filterField{kind: kind, columns: []string{"src_" + column, "dst_" + column}, values: values, unit: unit},
		&filterField{kind: kind, columns: []string{"src_" + column}, values: values, unit: unit},
		&filterField{kind: kind, columns: []string{"dst_" + column}, values: values, unit: unit}
}

// filterFields by canonical name; filterAliases maps other names to them.
var filterFields, filterAliases = func() (map[string]*filterField, map[string]string) {
	fields := map[string]*filterField{
		"type":              {kind: enumField, columns: []string{"event_type"}, values: eventTypeValues},
		"node":              {kind: stringField, columns: []string{"collector_id"}},
		"iface":             {kind: stringField, columns: []string{"interface"}},
		"iface.type":        {kind: roleField, columns: []string{"interface"}},
		"ipv":               {kind: numberField, columns: []string{"ip_version"}, unit: ipVersion},
		"process":           {kind: stringField, columns: []string{"process_command"}},
		"process.pod":       {kind: stringField, columns: []string{"process_pod"}},
		"process.container": {kind: stringField, columns: []string{"process_container"}},
		"process.side":      {kind: enumField, columns: []string{"process_side"}, values: sideValues},
		"route":             {kind: enumField, columns: []string{"route"}, values: routeValues},
		"peer":              {kind: stringField, columns: []string{"tailnet_peer", "tailnet_peer_name"}, entity: true},
		"domain":            {kind: domainField, columns: []string{"hostname", "dns_query", "tls_sni"}, entity: true},
		"rcode":             {kind: enumField, columns: []string{"dns_response_code"}, values: rcodeValues, shown: sortedKeys(rcodeNames)},
		"bytes":             {kind: numberField, columns: []string{"byte_count"}, unit: byteCount},
		"duration":          {kind: numberField, columns: []string{"duration"}, unit: milliseconds},
	}
	for name, column := range map[string]string{"ip": "ip", "port": "port", "kind": "kind", "ns": "namespace", "name": "name", "workload": "workload"} {
		kind, values, unit := stringField, map[string]string(nil), (func(string) (int64, error))(nil)
		switch name {
		case "ip":
			kind = ipField
		case "port":
			kind, unit = numberField, portNumber
		case "kind":
			kind, values = enumField, endpointKinds
		}
		fields[name], fields["src."+name], fields["dst."+name] = sided(kind, column, values, unit)
	}
	aliases := map[string]string{"namespace": "ns", "src.namespace": "src.ns", "dst.namespace": "dst.ns", "collector": "node", "interface": "iface",
		"iface.role": "iface.type", "command": "process", "host": "domain", "ipversion": "ipv", "event": "type"}
	return fields, aliases
}()

func lookupField(name string) (string, *filterField, bool) {
	name = strings.ToLower(name)
	if canonical, ok := filterAliases[name]; ok {
		name = canonical
	}
	field, ok := filterFields[name]
	return name, field, ok
}

// textColumns are searched by a bare word.
var textColumns = []string{"src_ip", "dst_ip", "hostname", "dns_query", "tls_sni", "src_name", "dst_name", "src_namespace", "dst_namespace", "src_workload", "dst_workload",
	"process_command", "process_pod", "process_container", "tailnet_peer", "tailnet_peer_name"}

// FilterError is a syntax or value error at a byte offset of the expression.
type FilterError struct {
	Pos     int
	Message string
}

func (e *FilterError) Error() string { return fmt.Sprintf("filter: %s (at %d)", e.Message, e.Pos) }

func filterErrorf(pos int, format string, args ...any) error {
	return &FilterError{Pos: pos, Message: fmt.Sprintf(format, args...)}
}

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokWord
	tokString
	tokOp
	tokOpen
	tokClose
	tokComma
)

type token struct {
	kind tokenKind
	text string
	pos  int
}

const wordStop = " \t\r\n()\",!=~<>"

func tokenize(input string) ([]token, error) {
	var tokens []token
	for i := 0; i < len(input); {
		c := input[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '(':
			tokens = append(tokens, token{tokOpen, "(", i})
			i++
		case c == ')':
			tokens = append(tokens, token{tokClose, ")", i})
			i++
		case c == ',':
			tokens = append(tokens, token{tokComma, ",", i})
			i++
		case c == '"':
			var text strings.Builder
			j := i + 1
			for ; j < len(input) && input[j] != '"'; j++ {
				if input[j] == '\\' && j+1 < len(input) {
					j++
				}
				text.WriteByte(input[j])
			}
			if j >= len(input) {
				return nil, filterErrorf(i, "unclosed quote")
			}
			tokens = append(tokens, token{tokString, text.String(), i})
			i = j + 1
		case strings.IndexByte("!=~<>", c) >= 0:
			op := string(c)
			if i+1 < len(input) {
				switch two := input[i : i+2]; two {
				case "!=", "!~", "<=", ">=":
					op = two
				}
			}
			tokens = append(tokens, token{tokOp, op, i})
			i += len(op)
		default:
			j := i
			for j < len(input) && strings.IndexByte(wordStop, input[j]) < 0 {
				j++
			}
			tokens = append(tokens, token{tokWord, input[i:j], i})
			i = j
		}
	}
	return append(tokens, token{kind: tokEOF, pos: len(input)}), nil
}

type parser struct {
	tokens []token
	at     int
	terms  int
}

func (p *parser) peek() token { return p.tokens[p.at] }

func (p *parser) next() token {
	t := p.tokens[p.at]
	if t.kind != tokEOF {
		p.at++
	}
	return t
}

func (p *parser) keyword(word string) bool {
	t := p.peek()
	return t.kind == tokWord && strings.EqualFold(t.text, word)
}

// parseFilter parses an expression; an empty one is nil and matches all.
func parseFilter(input string) (*expr, error) {
	if len(input) > maxFilterLength {
		return nil, filterErrorf(maxFilterLength, "longer than %d characters", maxFilterLength)
	}
	tokens, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 1 {
		return nil, nil
	}
	p := &parser{tokens: tokens}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tokEOF {
		return nil, filterErrorf(t.pos, "unexpected %q", t.text)
	}
	return e, nil
}

func (p *parser) or() (*expr, error) {
	first, err := p.and()
	if err != nil {
		return nil, err
	}
	terms := []*expr{first}
	for p.keyword("or") {
		p.next()
		term, err := p.and()
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return join(exprOr, terms), nil
}

func (p *parser) and() (*expr, error) {
	first, err := p.unary()
	if err != nil {
		return nil, err
	}
	terms := []*expr{first}
	for {
		if p.keyword("and") {
			p.next()
		} else if t := p.peek(); t.kind == tokEOF || t.kind == tokClose || p.keyword("or") {
			break
		}
		term, err := p.unary()
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return join(exprAnd, terms), nil
}

func (p *parser) unary() (*expr, error) {
	if p.terms++; p.terms > maxFilterTerms {
		return nil, filterErrorf(p.peek().pos, "more than %d terms", maxFilterTerms)
	}
	t := p.peek()
	switch {
	case p.keyword("not") || (t.kind == tokOp && t.text == "!"):
		p.next()
		inner, err := p.unary()
		if err != nil {
			return nil, err
		}
		return negate(inner), nil
	case t.kind == tokOpen:
		p.next()
		inner, err := p.or()
		if err != nil {
			return nil, err
		}
		if c := p.next(); c.kind != tokClose {
			return nil, filterErrorf(c.pos, "missing )")
		}
		return inner, nil
	case t.kind == tokWord && (p.keyword("and") || p.keyword("or")):
		return nil, filterErrorf(t.pos, "a condition is missing before %q", t.text)
	case t.kind == tokWord || t.kind == tokString:
		p.next()
		if op := p.peek(); op.kind == tokOp && op.text != "!" {
			if t.kind == tokString {
				return nil, filterErrorf(t.pos, "a field name cannot be quoted")
			}
			name, negated := t.text, false
			if len(name) > 1 && name[0] == '-' {
				name, negated = name[1:], true
			}
			canonical, field, ok := lookupField(name)
			if !ok {
				return nil, filterErrorf(t.pos, "unknown field %q", name)
			}
			p.next()
			values, err := p.values()
			if err != nil {
				return nil, err
			}
			compare, err := newCompare(canonical, field, op.text, values, t.pos)
			if err != nil {
				return nil, err
			}
			if negated {
				return negate(compare), nil
			}
			return compare, nil
		}
		text, negated := t.text, false
		if t.kind == tokWord && len(text) > 1 && text[0] == '-' {
			text, negated = text[1:], true
		}
		term := &expr{kind: exprText, raw: []string{text}, norm: []value{{text: text}}}
		if negated {
			return negate(term), nil
		}
		return term, nil
	}
	if t.kind == tokEOF {
		return nil, filterErrorf(t.pos, "a condition is missing at the end")
	}
	return nil, filterErrorf(t.pos, "unexpected %q", t.text)
}

func (p *parser) values() ([]string, error) {
	t := p.next()
	switch t.kind {
	case tokWord, tokString:
		return []string{t.text}, nil
	case tokOpen:
		var values []string
		for {
			v := p.next()
			if v.kind != tokWord && v.kind != tokString {
				return nil, filterErrorf(v.pos, "a value is missing in the list")
			}
			if values = append(values, v.text); len(values) > maxFilterValues {
				return nil, filterErrorf(v.pos, "more than %d values", maxFilterValues)
			}
			switch sep := p.next(); sep.kind {
			case tokClose:
				return values, nil
			case tokComma:
			default:
				return nil, filterErrorf(sep.pos, "expected , or ) in the list")
			}
		}
	}
	return nil, filterErrorf(t.pos, "a value is missing after the operator")
}

func join(kind exprKind, terms []*expr) *expr {
	if len(terms) == 1 {
		return terms[0]
	}
	var flat []*expr
	for _, term := range terms {
		if term.kind == kind {
			flat = append(flat, term.terms...)
		} else {
			flat = append(flat, term)
		}
	}
	return &expr{kind: kind, terms: flat}
}

func negate(inner *expr) *expr { return &expr{kind: exprNot, inner: inner} }

// andFilters joins filters with and; nil ones match all.
func andFilters(filters ...*expr) *expr {
	var terms []*expr
	for _, f := range filters {
		if f != nil {
			terms = append(terms, f)
		}
	}
	if len(terms) == 0 {
		return nil
	}
	return join(exprAnd, terms)
}

// newCompare validates and normalizes a comparison.
func newCompare(name string, field *filterField, op string, raw []string, pos int) (*expr, error) {
	e := &expr{kind: exprCompare, field: field, name: name, op: op, raw: raw}
	contains := op == "~" || op == "!~"
	ordered := op == "<" || op == "<=" || op == ">" || op == ">="
	if ordered && (field.kind != numberField || len(raw) != 1) {
		return nil, filterErrorf(pos, "%s %s needs one number", name, op)
	}
	if contains && (field.kind == numberField || field.kind == roleField) {
		return nil, filterErrorf(pos, "%s cannot use %s", name, op)
	}
	for _, text := range raw {
		v, err := field.normalize(text, contains)
		if err != nil {
			return nil, filterErrorf(pos, "%s: %v", name, err)
		}
		e.norm = append(e.norm, v)
	}
	return e, nil
}

func (f *filterField) normalize(text string, contains bool) (value, error) {
	if contains {
		if text == "" {
			return value{}, fmt.Errorf("contains needs some text")
		}
		return value{text: text}, nil
	}
	none := strings.EqualFold(text, "none")
	switch f.kind {
	case enumField:
		stored, ok := f.values[strings.ToLower(strings.TrimSpace(text))]
		if !ok {
			names := f.shown
			if names == nil {
				names = enumNames(f.values)
			}
			return value{}, fmt.Errorf("%q is not one of %s", text, strings.Join(names, ", "))
		}
		return value{text: stored}, nil
	case roleField:
		if _, ok := interfaceRoles[strings.ToLower(text)]; !ok {
			return value{}, fmt.Errorf("%q is not one of %s", text, strings.Join(sortedKeys(interfaceRoles), ", "))
		}
		return value{role: strings.ToLower(text)}, nil
	case numberField:
		if lo, hi, ok := strings.Cut(text, "-"); ok && lo != "" {
			from, err := f.unit(lo)
			if err != nil {
				return value{}, err
			}
			to, err := f.unit(hi)
			if err != nil {
				return value{}, err
			}
			if to < from {
				return value{}, fmt.Errorf("range %s is backwards", text)
			}
			return value{lo: from, hi: to}, nil
		}
		n, err := f.unit(text)
		return value{lo: n, hi: n}, err
	case ipField:
		if none {
			return value{}, nil
		}
		if strings.Contains(text, "/") {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return value{}, fmt.Errorf("%q is not an address prefix such as 10.0.0.0/8", text)
			}
			return value{prefix: prefix.Masked()}, nil
		}
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return value{}, fmt.Errorf("%q is not an address; use ~ to match part of one", text)
		}
		return value{text: addr.String()}, nil
	case domainField:
		if none {
			return value{}, nil
		}
		name := asciiLower(strings.TrimSuffix(text, "."))
		if name == "" {
			return value{}, fmt.Errorf("a name is missing")
		}
		return value{text: name}, nil
	}
	if none {
		return value{}, nil
	}
	if text == "" {
		return value{}, fmt.Errorf("an empty value matches nothing; use none")
	}
	return value{text: text}, nil
}

func enumNames(values map[string]string) []string {
	return sortedKeys(values)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func portNumber(text string) (int64, error) {
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port (0-65535)", text)
	}
	return n, nil
}

func ipVersion(text string) (int64, error) {
	if text != "4" && text != "6" {
		return 0, fmt.Errorf("%q is not 4 or 6", text)
	}
	return int64(text[0] - '0'), nil
}

// byteCount reads 1500, 1.5k, 2M or 1g (powers of 1024, as the page shows).
func byteCount(text string) (int64, error) {
	return scaled(text, map[string]float64{"": 1, "b": 1, "k": 1 << 10, "kb": 1 << 10, "kib": 1 << 10, "m": 1 << 20, "mb": 1 << 20, "mib": 1 << 20, "g": 1 << 30, "gb": 1 << 30, "gib": 1 << 30})
}

// milliseconds reads 250, 250ms, 1.5s, 2m or 1h.
func milliseconds(text string) (int64, error) {
	return scaled(text, map[string]float64{"": 1, "ms": 1, "s": 1000, "m": 60_000, "min": 60_000, "h": 3_600_000})
}

func scaled(text string, units map[string]float64) (int64, error) {
	lower := strings.ToLower(text)
	end := strings.IndexFunc(lower, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if end < 0 {
		end = len(lower)
	}
	n, err := strconv.ParseFloat(lower[:end], 64)
	unit, ok := units[lower[end:]]
	if err != nil || !ok || n < 0 {
		return 0, fmt.Errorf("%q is not a number with a unit (%s)", text, strings.Join(sortedKeys(units)[1:], ", "))
	}
	return int64(n * unit), nil
}

// String writes the expression back, with canonical field names and the
// values as written; filter.ts writes the same text.
func (e *expr) String() string {
	if e == nil {
		return ""
	}
	switch e.kind {
	case exprAnd, exprOr:
		parts := make([]string, len(e.terms))
		for i, term := range e.terms {
			parts[i] = term.String()
			if e.kind == exprAnd && term.kind == exprOr {
				parts[i] = "(" + parts[i] + ")"
			}
		}
		if e.kind == exprAnd {
			return strings.Join(parts, " and ")
		}
		return strings.Join(parts, " or ")
	case exprNot:
		inner := e.inner.String()
		if e.inner.kind == exprAnd || e.inner.kind == exprOr {
			inner = "(" + inner + ")"
		}
		return "not " + inner
	case exprText:
		return quoteValue(e.raw[0], true)
	}
	values := make([]string, len(e.raw))
	for i, raw := range e.raw {
		values[i] = quoteValue(raw, false)
	}
	if len(values) == 1 {
		return e.name + " " + e.op + " " + values[0]
	}
	return e.name + " " + e.op + " (" + strings.Join(values, ", ") + ")"
}

// quoteValue quotes a value unless it reads back as the same word. A text
// term also needs quotes when it would read as a keyword or a negation.
func quoteValue(text string, term bool) string {
	plain := text != "" && !strings.ContainsAny(text, wordStop+"\\")
	if term && plain {
		lower := strings.ToLower(text)
		plain = lower != "and" && lower != "or" && lower != "not" && text[0] != '-'
	}
	if plain {
		return text
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// likeContains is a LIKE pattern for text containing s.
func likeContains(s string) string { return "%" + likeEscape(s) + "%" }

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// sql compiles the expression to a WHERE clause. Every column is read
// through COALESCE, so a NULL compares as unset instead of making the whole
// condition (and its negation) unknown.
func (e *expr) sql() (string, []any) {
	switch e.kind {
	case exprAnd, exprOr:
		join := " AND "
		if e.kind == exprOr {
			join = " OR "
		}
		parts := make([]string, len(e.terms))
		var args []any
		for i, term := range e.terms {
			clause, termArgs := term.sql()
			parts[i], args = "("+clause+")", append(args, termArgs...)
		}
		return strings.Join(parts, join), args
	case exprNot:
		clause, args := e.inner.sql()
		return "NOT (" + clause + ")", args
	case exprText:
		parts := make([]string, len(textColumns))
		args := make([]any, len(textColumns))
		for i, column := range textColumns {
			parts[i], args[i] = "COALESCE("+column+", '') LIKE ? ESCAPE '\\'", likeContains(e.norm[0].text)
		}
		return strings.Join(parts, " OR "), args
	}
	negated := e.op == "!=" || e.op == "!~"
	var parts []string
	var args []any
	if e.field.entity && e.op != "~" && e.op != "!~" && e.hasNone() {
		// An unset entity: every one of its columns is unset.
		var unset []string
		for _, column := range e.field.columns {
			unset = append(unset, "COALESCE("+column+", '') = ''")
		}
		parts = append(parts, "("+strings.Join(unset, " AND ")+")")
	}
	for _, column := range e.field.columns {
		clause, columnArgs := e.columnSQL(column)
		if clause != "" {
			parts, args = append(parts, clause), append(args, columnArgs...)
		}
	}
	clause := strings.Join(parts, " OR ")
	if clause == "" {
		clause = "0"
	}
	if negated {
		return "NOT (" + clause + ")", args
	}
	return clause, args
}

func (e *expr) hasNone() bool {
	for _, v := range e.norm {
		if v.text == "" && !v.prefix.IsValid() && v.role == "" {
			return true
		}
	}
	return false
}

func (e *expr) columnSQL(column string) (string, []any) {
	text := "COALESCE(" + column + ", '')"
	var parts []string
	var args []any
	switch {
	case e.op == "~" || e.op == "!~":
		for _, v := range e.norm {
			parts, args = append(parts, text+" LIKE ? ESCAPE '\\'"), append(args, likeContains(v.text))
		}
	case e.field.kind == numberField:
		number := "COALESCE(" + column + ", 0)"
		for _, v := range e.norm {
			switch e.op {
			case "<", "<=", ">", ">=":
				parts, args = append(parts, number+" "+e.op+" ?"), append(args, v.lo)
			default:
				if v.lo == v.hi {
					parts, args = append(parts, number+" = ?"), append(args, v.lo)
				} else {
					parts, args = append(parts, number+" BETWEEN ? AND ?"), append(args, v.lo, v.hi)
				}
			}
		}
	case e.field.kind == roleField:
		for _, v := range e.norm {
			role := interfaceRoles[v.role]
			clause := "(" + globSQL(text, role.match) + ")"
			if len(role.except) > 0 {
				clause = "(" + clause + " AND NOT (" + globSQL(text, role.except) + "))"
			}
			parts = append(parts, clause)
			for _, pattern := range append(append([]string{}, role.match...), role.except...) {
				args = append(args, pattern)
			}
		}
	case e.field.kind == domainField:
		name := "lower(rtrim(" + text + ", '.'))"
		for _, v := range e.norm {
			if v.text == "" {
				continue // Handled as an unset entity.
			}
			parts, args = append(parts, "("+name+" = ? OR "+name+" LIKE ? ESCAPE '\\')"), append(args, v.text, "%."+likeEscape(v.text))
		}
	case e.field.kind == ipField:
		var exact []any
		for _, v := range e.norm {
			if v.prefix.IsValid() {
				parts, args = append(parts, "ip_in_prefix("+text+", ?)"), append(args, v.prefix.String())
			} else if !e.field.entity || v.text != "" {
				exact = append(exact, v.text)
			}
		}
		if len(exact) > 0 {
			parts, args = append(parts, text+" IN ("+placeholders(len(exact))+")"), append(args, exact...)
		}
	default:
		var exact []any
		for _, v := range e.norm {
			if !e.field.entity || v.text != "" {
				exact = append(exact, v.text)
			}
		}
		if len(exact) > 0 {
			parts, args = append(parts, text+" IN ("+placeholders(len(exact))+")"), append(args, exact...)
		}
	}
	return strings.Join(parts, " OR "), args
}

func globSQL(column string, patterns []string) string {
	parts := make([]string, len(patterns))
	for i := range patterns {
		parts[i] = column + " GLOB ?"
	}
	return strings.Join(parts, " OR ")
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

// matches evaluates the expression for one event, as its SQL would.
func (e *expr) matches(event *database.NetworkEvent) bool {
	if e == nil {
		return true
	}
	switch e.kind {
	case exprAnd:
		for _, term := range e.terms {
			if !term.matches(event) {
				return false
			}
		}
		return true
	case exprOr:
		for _, term := range e.terms {
			if term.matches(event) {
				return true
			}
		}
		return false
	case exprNot:
		return !e.inner.matches(event)
	case exprText:
		needle := asciiLower(e.norm[0].text)
		for _, column := range textColumns {
			if strings.Contains(asciiLower(eventText(event, column)), needle) {
				return true
			}
		}
		return false
	}
	matched := false
	if e.field.entity && e.op != "~" && e.op != "!~" && e.hasNone() {
		matched = true
		for _, column := range e.field.columns {
			if eventText(event, column) != "" {
				matched = false
			}
		}
	}
	for _, column := range e.field.columns {
		if matched {
			break
		}
		matched = e.columnMatches(event, column)
	}
	if e.op == "!=" || e.op == "!~" {
		return !matched
	}
	return matched
}

func (e *expr) columnMatches(event *database.NetworkEvent, column string) bool {
	if e.field.kind == numberField && e.op != "~" && e.op != "!~" {
		n := eventNumber(event, column)
		for _, v := range e.norm {
			switch e.op {
			case "<":
				return n < v.lo
			case "<=":
				return n <= v.lo
			case ">":
				return n > v.lo
			case ">=":
				return n >= v.lo
			}
			if n >= v.lo && n <= v.hi {
				return true
			}
		}
		return false
	}
	text := eventText(event, column)
	for _, v := range e.norm {
		switch {
		case e.op == "~" || e.op == "!~":
			if strings.Contains(asciiLower(text), asciiLower(v.text)) {
				return true
			}
		case e.field.kind == roleField:
			role := interfaceRoles[v.role]
			if globAny(role.match, text) && !globAny(role.except, text) {
				return true
			}
		case e.field.kind == domainField:
			name := asciiLower(strings.TrimRight(text, "."))
			if v.text != "" && (name == v.text || strings.HasSuffix(name, "."+v.text)) {
				return true
			}
		case e.field.kind == ipField && v.prefix.IsValid():
			if database.IPInPrefix(text, v.prefix.String()) {
				return true
			}
		default:
			if text == v.text && (!e.field.entity || v.text != "") {
				return true
			}
		}
	}
	return false
}

func globAny(patterns []string, text string) bool {
	for _, pattern := range patterns {
		if ok, _ := path.Match(pattern, text); ok {
			return true
		}
	}
	return false
}

func eventText(e *database.NetworkEvent, column string) string {
	switch column {
	case "event_type":
		return string(e.EventType)
	case "collector_id":
		return e.CollectorID
	case "interface":
		return e.Interface
	case "src_ip":
		return e.SrcIP
	case "dst_ip":
		return e.DstIP
	case "src_kind":
		return e.SrcKind
	case "dst_kind":
		return e.DstKind
	case "src_namespace":
		return e.SrcNamespace
	case "dst_namespace":
		return e.DstNamespace
	case "src_name":
		return e.SrcName
	case "dst_name":
		return e.DstName
	case "src_workload":
		return e.SrcWorkload
	case "dst_workload":
		return e.DstWorkload
	case "process_command":
		return e.ProcessCommand
	case "process_pod":
		return e.ProcessPod
	case "process_container":
		return e.ProcessContainer
	case "process_side":
		return e.ProcessSide
	case "route":
		return e.Route
	case "tailnet_peer":
		return e.TailnetPeer
	case "tailnet_peer_name":
		return e.TailnetPeerName
	case "hostname":
		return e.Hostname
	case "dns_query":
		return e.DNSQuery
	case "tls_sni":
		return e.TLSSNI
	case "dns_response_code":
		return e.DNSResponseCode
	}
	panic("filter: no text column " + column)
}

func eventNumber(e *database.NetworkEvent, column string) int64 {
	switch column {
	case "ip_version":
		return int64(e.IPVersion)
	case "src_port":
		return int64(e.SrcPort)
	case "dst_port":
		return int64(e.DstPort)
	case "byte_count":
		return e.ByteCount
	case "duration":
		return e.Duration
	}
	panic("filter: no number column " + column)
}

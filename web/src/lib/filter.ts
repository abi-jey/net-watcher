/**
 * Event filter expressions, read exactly as the server reads them
 * (internal/web/filter.go; filter.vectors.json keeps the two in step):
 *
 *   src.kind != pod and (dst.kind = node or port = 53) and not ns = kube-system
 *
 * The page keeps a filter as text in the URL and edits it as a list of
 * conditions that must all hold, each a single condition or several
 * alternatives joined by "or".
 */

export type Op = '=' | '!=' | '~' | '!~' | '<' | '<=' | '>' | '>=';

export type Term =
  | { kind: 'and' | 'or'; terms: Term[] }
  | { kind: 'not'; inner: Term }
  | { kind: 'compare'; field: string; op: Op; values: string[] }
  | { kind: 'text'; text: string };

export type Compare = Extract<Term, { kind: 'compare' }>;

export type FieldKind = 'string' | 'enum' | 'ip' | 'number' | 'domain' | 'role';

export interface Field {
  name: string;
  label: string;
  group: string;
  kind: FieldKind;
  help: string;
  /** Values an enum or role field accepts, as the server spells them. */
  values?: { id: string; label: string }[];
}

const kinds = [{ id: 'pod', label: 'pod' }, { id: 'node', label: 'node' }, { id: 'service', label: 'service' }, { id: 'endpoint', label: 'endpoint' }, { id: 'none', label: 'outside the cluster' }];
export const eventTypes = ['TCP_START', 'TCP_END', 'UDP_START', 'UDP_END', 'DNS', 'TLS_SNI', 'ICMP', 'TIMEOUT', 'GAP'];
const roles = [
  { id: 'pod', label: 'pod link' }, { id: 'overlay', label: 'overlay' }, { id: 'cluster-host', label: 'cluster host' }, { id: 'tailscale', label: 'Tailscale' },
  { id: 'wireguard', label: 'WireGuard' }, { id: 'bridge', label: 'bridge' }, { id: 'wifi', label: 'Wi-Fi' }, { id: 'uplink', label: 'uplink' },
  { id: 'tunnel', label: 'tunnel' }, { id: 'loopback', label: 'loopback' },
];

function sided(name: string, label: string, kind: FieldKind, help: string, values?: Field['values']): Field[] {
  return [
    { name, label, group: 'Either end', kind, help: `${help} at either end. "is not" means neither end.`, values },
    { name: `src.${name}`, label: `source ${label}`, group: 'Source', kind, help: `${help} of the source.`, values },
    { name: `dst.${name}`, label: `destination ${label}`, group: 'Destination', kind, help: `${help} of the destination.`, values },
  ];
}

/** A connection records up to two processes: the one that opened it and, when on the same node, the one that accepted it. */
function processFields(name: string, label: string, help: string): Field[] {
  return [
    { name, label, group: 'Process', kind: 'string', help: `${help} at either end. "is not" means neither end.` },
    { name: `src.${name}`, label: label.replace('process', 'opening process'), group: 'Process', kind: 'string', help: `${help} that opened the connection (owns the source socket).` },
    { name: `dst.${name}`, label: label.replace('process', 'accepting process'), group: 'Process', kind: 'string', help: `${help} that accepted the connection (owns the destination socket).` },
  ];
}

export const fields: Field[] = [
  { name: 'type', label: 'type', group: 'Event', kind: 'enum', help: 'Event type.', values: [...eventTypes, 'TCP', 'UDP', 'HOURLY'].map(id => ({ id, label: id })) },
  { name: 'bytes', label: 'bytes', group: 'Event', kind: 'number', help: 'Bytes transferred: 1500, 1.5k, 2M (powers of 1024).' },
  { name: 'duration', label: 'duration', group: 'Event', kind: 'number', help: 'Duration: 250ms, 2s, 5m.' },
  { name: 'ipv', label: 'IP version', group: 'Event', kind: 'number', help: '4 or 6.' },
  { name: 'domain', label: 'domain', group: 'Event', kind: 'domain', help: 'Host name, DNS query or TLS SNI; "is" includes subdomains.' },
  { name: 'rcode', label: 'DNS result', group: 'Event', kind: 'enum', help: 'DNS response code of a DNS response; none on queries.', values: [
    { id: 'NOERROR', label: 'NOERROR (answered)' }, { id: 'NXDOMAIN', label: 'NXDOMAIN (no such name)' }, { id: 'SERVFAIL', label: 'SERVFAIL (server failure)' },
    { id: 'REFUSED', label: 'REFUSED' }, { id: 'FORMERR', label: 'FORMERR (malformed query)' }, { id: 'NOTIMP', label: 'NOTIMP (not implemented)' }, { id: 'none', label: 'none (queries)' }] },
  ...sided('ip', 'address', 'ip', 'Address, or prefix such as 10.0.0.0/8,'),
  ...sided('port', 'port', 'number', 'Port, or range such as 1000-2000,'),
  ...sided('kind', 'kind', 'enum', 'Kubernetes kind', kinds),
  ...sided('ns', 'namespace', 'string', 'Kubernetes namespace'),
  ...sided('name', 'name', 'string', 'Pod, node or service name'),
  ...sided('workload', 'workload', 'string', 'Workload as Kind/name, such as Deployment/coredns'),
  ...processFields('process', 'process', 'Command of the process'),
  ...processFields('process.pod', 'process pod', 'Pod (namespace/name) of the process; none for a process outside any pod,'),
  ...processFields('process.container', 'process container', 'Container of the process'),
  { name: 'process.side', label: 'process side', group: 'Process', kind: 'enum', help: 'Which processes are known: src when the one that opened the connection is, dst when only the one that accepted it is; none when neither.',
    values: [{ id: 'src', label: 'opener known' }, { id: 'dst', label: 'only the acceptor known' }, { id: 'none', label: 'not identified' }] },
  { name: 'node', label: 'node', group: 'Capture', kind: 'string', help: 'Collector (node) that captured the packet.' },
  { name: 'iface', label: 'interface', group: 'Capture', kind: 'string', help: 'Interface name, such as tailscale0.' },
  { name: 'iface.type', label: 'interface type', group: 'Capture', kind: 'role', help: 'What the interface connects.', values: roles },
  { name: 'route', label: 'Tailscale route', group: 'Capture', kind: 'enum', help: 'Traffic this node forwarded for a tailnet device, or sent into the tailnet.', values: [{ id: 'exit-node', label: 'exit node' }, { id: 'subnet-router', label: 'subnet router' }, { id: 'via-tailnet', label: 'into the tailnet' }, { id: 'none', label: 'none' }] },
  { name: 'peer', label: 'tailnet device', group: 'Capture', kind: 'string', help: 'Tailnet device (address or name) the node forwarded for.' },
];

const aliases: Record<string, string> = {
  namespace: 'ns', 'src.namespace': 'src.ns', 'dst.namespace': 'dst.ns', collector: 'node', interface: 'iface', 'iface.role': 'iface.type',
  command: 'process', 'src.command': 'src.process', 'dst.command': 'dst.process', host: 'domain', ipversion: 'ipv', event: 'type',
};

export function field(name: string): Field | undefined {
  const lower = name.toLowerCase();
  const canonical = aliases[lower] ?? lower;
  return fields.find(candidate => candidate.name === canonical);
}

export class FilterError extends Error {
  readonly pos: number;
  constructor(pos: number, message: string) {
    super(message);
    this.pos = pos;
  }
}

type Token = { kind: 'eof' | 'word' | 'string' | 'op' | 'open' | 'close' | 'comma'; text: string; pos: number };

const wordStop = ' \t\r\n()",!=~<>';

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  for (let i = 0; i < input.length;) {
    const c = input[i];
    if (' \t\r\n'.includes(c)) { i++; continue; }
    if (c === '(' || c === ')' || c === ',') { tokens.push({ kind: c === '(' ? 'open' : c === ')' ? 'close' : 'comma', text: c, pos: i }); i++; continue; }
    if (c === '"') {
      let text = '';
      let j = i + 1;
      for (; j < input.length && input[j] !== '"'; j++) {
        if (input[j] === '\\' && j + 1 < input.length) j++;
        text += input[j];
      }
      if (j >= input.length) throw new FilterError(i, 'unclosed quote');
      tokens.push({ kind: 'string', text, pos: i });
      i = j + 1;
      continue;
    }
    if ('!=~<>'.includes(c)) {
      const two = input.slice(i, i + 2);
      const op = ['!=', '!~', '<=', '>='].includes(two) ? two : c;
      tokens.push({ kind: 'op', text: op, pos: i });
      i += op.length;
      continue;
    }
    let j = i;
    while (j < input.length && !wordStop.includes(input[j])) j++;
    tokens.push({ kind: 'word', text: input.slice(i, j), pos: i });
    i = j;
  }
  tokens.push({ kind: 'eof', text: '', pos: input.length });
  return tokens;
}

/** Parses a filter; an empty one is null and matches every event. */
export function parse(input: string): Term | null {
  const tokens = tokenize(input);
  if (tokens.length === 1) return null;
  let at = 0;
  const peek = () => tokens[at];
  const next = () => (tokens[at].kind === 'eof' ? tokens[at] : tokens[at++]);
  const keyword = (word: string) => peek().kind === 'word' && peek().text.toLowerCase() === word;

  const or = (): Term => {
    const terms = [and()];
    while (keyword('or')) { next(); terms.push(and()); }
    return join('or', terms);
  };
  const and = (): Term => {
    const terms = [unary()];
    for (;;) {
      if (keyword('and')) next();
      else if (peek().kind === 'eof' || peek().kind === 'close' || keyword('or')) break;
      terms.push(unary());
    }
    return join('and', terms);
  };
  const values = (): string[] => {
    const t = next();
    if (t.kind === 'word' || t.kind === 'string') return [t.text];
    if (t.kind === 'open') {
      const list: string[] = [];
      for (;;) {
        const v = next();
        if (v.kind !== 'word' && v.kind !== 'string') throw new FilterError(v.pos, 'a value is missing in the list');
        list.push(v.text);
        const separator = next();
        if (separator.kind === 'close') return list;
        if (separator.kind !== 'comma') throw new FilterError(separator.pos, 'expected , or ) in the list');
      }
    }
    throw new FilterError(t.pos, 'a value is missing after the operator');
  };
  const unary = (): Term => {
    const t = peek();
    if (keyword('not') || (t.kind === 'op' && t.text === '!')) { next(); return { kind: 'not', inner: unary() }; }
    if (t.kind === 'open') {
      next();
      const inner = or();
      const close = next();
      if (close.kind !== 'close') throw new FilterError(close.pos, 'missing )');
      return inner;
    }
    if (t.kind === 'word' && (keyword('and') || keyword('or'))) throw new FilterError(t.pos, `a condition is missing before "${t.text}"`);
    if (t.kind === 'word' || t.kind === 'string') {
      next();
      const op = peek();
      if (op.kind === 'op' && op.text !== '!') {
        if (t.kind === 'string') throw new FilterError(t.pos, 'a field name cannot be quoted');
        let name = t.text;
        let negated = false;
        if (name.length > 1 && name[0] === '-') { name = name.slice(1); negated = true; }
        const known = field(name);
        if (!known) throw new FilterError(t.pos, `unknown field "${name}"`);
        next();
        const compare: Term = { kind: 'compare', field: known.name, op: op.text as Op, values: values() };
        return negated ? { kind: 'not', inner: compare } : compare;
      }
      let text = t.text;
      let negated = false;
      if (t.kind === 'word' && text.length > 1 && text[0] === '-') { text = text.slice(1); negated = true; }
      const term: Term = { kind: 'text', text };
      return negated ? { kind: 'not', inner: term } : term;
    }
    if (t.kind === 'eof') throw new FilterError(t.pos, 'a condition is missing at the end');
    throw new FilterError(t.pos, `unexpected "${t.text}"`);
  };

  const term = or();
  if (peek().kind !== 'eof') throw new FilterError(peek().pos, `unexpected "${peek().text}"`);
  return term;
}

function join(kind: 'and' | 'or', terms: Term[]): Term {
  if (terms.length === 1) return terms[0];
  return { kind, terms: terms.flatMap(term => (term.kind === kind ? term.terms : [term])) };
}

/** Parses, returning the error instead of throwing. */
export function tryParse(input: string): { term: Term | null; error?: FilterError } {
  try {
    return { term: parse(input) };
  } catch (error) {
    if (error instanceof FilterError) return { term: null, error };
    throw error;
  }
}

function quote(text: string, term: boolean): string {
  let plain = text !== '' && ![...wordStop, '\\'].some(c => text.includes(c));
  if (term && plain) {
    const lower = text.toLowerCase();
    plain = lower !== 'and' && lower !== 'or' && lower !== 'not' && text[0] !== '-';
  }
  return plain ? text : `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Writes a filter as the server's canonical text. */
export function format(term: Term | null): string {
  if (!term) return '';
  switch (term.kind) {
    case 'and': return term.terms.map(t => (t.kind === 'or' ? `(${format(t)})` : format(t))).join(' and ');
    case 'or': return term.terms.map(format).join(' or ');
    case 'not': return `not ${term.inner.kind === 'and' || term.inner.kind === 'or' ? `(${format(term.inner)})` : format(term.inner)}`;
    case 'text': return quote(term.text, true);
    case 'compare': {
      const values = term.values.map(value => quote(value, false));
      return `${term.field} ${term.op} ${values.length === 1 ? values[0] : `(${values.join(', ')})`}`;
    }
  }
}

/** The conditions that must all hold. */
export function conditions(term: Term | null): Term[] {
  if (!term) return [];
  return term.kind === 'and' ? term.terms : [term];
}

export function allOf(terms: Term[]): Term | null {
  if (!terms.length) return null;
  return join('and', terms);
}

export function anyOf(terms: Term[]): Term {
  return join('or', terms);
}

/** Alternatives of a condition: itself unless it is an "or". */
export function alternatives(term: Term): Term[] {
  return term.kind === 'or' ? term.terms : [term];
}

/** A condition simple enough to show and edit as one chip. */
export function isSimple(term: Term): boolean {
  return term.kind === 'compare' || term.kind === 'text' || (term.kind === 'not' && (term.inner.kind === 'compare' || term.inner.kind === 'text'));
}

const opposite: Record<Op, Op> = { '=': '!=', '!=': '=', '~': '!~', '!~': '~', '<': '>=', '>=': '<', '>': '<=', '<=': '>' };

/** The condition's negation, as simply as it can be written. */
export function negate(term: Term): Term {
  if (term.kind === 'compare') return { ...term, op: opposite[term.op] };
  if (term.kind === 'not') return term.inner;
  return { kind: 'not', inner: term };
}

const opLabels: Record<Op, string> = { '=': 'is', '!=': 'is not', '~': 'contains', '!~': 'does not contain', '<': 'below', '<=': 'at most', '>': 'above', '>=': 'at least' };

export function opLabel(op: Op): string {
  return opLabels[op];
}

/** Operators a field takes. */
export function opsFor(kind: FieldKind): Op[] {
  switch (kind) {
    case 'number': return ['=', '!=', '<', '<=', '>', '>='];
    case 'enum': case 'role': return ['=', '!='];
    default: return ['=', '!=', '~', '!~'];
  }
}

function valueLabel(f: Field | undefined, value: string): string {
  return f?.values?.find(option => option.id.toLowerCase() === value.toLowerCase())?.label ?? value;
}

/** Plain-language reading of a simple condition. */
export function describe(term: Term): { field: string; op: string; values: string[] } {
  if (term.kind === 'text') return { field: 'text', op: 'contains', values: [term.text] };
  if (term.kind === 'not' && term.inner.kind === 'text') return { field: 'text', op: 'does not contain', values: [term.inner.text] };
  if (term.kind === 'not' && term.inner.kind === 'compare') {
    const inner = describe(term.inner);
    return { ...inner, op: `not ${inner.op}` };
  }
  if (term.kind === 'compare') {
    const f = field(term.field);
    return { field: f?.label ?? term.field, op: opLabel(term.op), values: term.values.map(value => valueLabel(f, value)) };
  }
  return { field: '', op: '', values: [format(term)] };
}

/**
 * Adds a condition from a clicked tag: showing only a value replaces a
 * condition that showed only another value of the field; hiding a value adds
 * it to the values already hidden. A combined condition replaces itself or
 * its negation.
 */
export function addCondition(filter: Term | null, added: Term): Term | null {
  const terms = conditions(filter);
  if (added.kind !== 'compare') {
    const same = [format(added), format(negate(added))];
    return allOf([...terms.filter(t => !same.includes(format(t))), added]);
  }
  const same = terms.findIndex(t => t.kind === 'compare' && t.field === added.field && t.op === added.op);
  if (same >= 0) {
    const existing = terms[same] as Compare;
    const replaced: Compare = added.op === '!='
      ? { ...existing, values: [...existing.values, ...added.values.filter(value => !existing.values.includes(value))] }
      : added;
    return allOf(terms.map((t, i) => (i === same ? replaced : t)));
  }
  return allOf([...terms, added]);
}

/** The condition that a field has one of the values. */
export function is(name: string, ...values: string[]): Compare {
  return { kind: 'compare', field: name, op: '=', values };
}

/** Whether a condition compares a field anywhere inside it. */
export function mentions(term: Term, name: string): boolean {
  switch (term.kind) {
    case 'and': case 'or': return term.terms.some(t => mentions(t, name));
    case 'not': return mentions(term.inner, name);
    case 'compare': return term.field === name;
    case 'text': return false;
  }
}

/** Event types the filter hides, when one condition on type decides it. */
export function hiddenTypes(filter: Term | null): { hidden: string[]; index: number } | null {
  const terms = conditions(filter);
  const index = terms.findIndex(t => t.kind === 'compare' && t.field === 'type');
  if (index < 0) return terms.some(t => mentions(t, 'type')) ? null : { hidden: [], index: -1 };
  const t = terms[index] as Compare;
  const values = t.values.map(value => value.toUpperCase());
  if (t.op === '!=') return { hidden: values, index };
  if (t.op === '=') return { hidden: eventTypes.filter(type => !values.includes(type)), index };
  return null;
}

/** The filter with an event type shown or hidden. */
export function toggleType(filter: Term | null, type: string): Term | null {
  const state = hiddenTypes(filter);
  if (!state) return filter;
  const hidden = state.hidden.includes(type) ? state.hidden.filter(t => t !== type) : [...state.hidden, type];
  const terms = conditions(filter);
  const shown = eventTypes.filter(t => !hidden.includes(t));
  const condition: Compare | null = !hidden.length ? null
    : hidden.length <= shown.length ? { kind: 'compare', field: 'type', op: '!=', values: eventTypes.filter(t => hidden.includes(t)) }
      : { kind: 'compare', field: 'type', op: '=', values: shown };
  const next = state.index < 0 ? [...terms, ...(condition ? [condition] : [])]
    : terms.flatMap((t, i) => (i === state.index ? (condition ? [condition] : []) : [t]));
  return allOf(next);
}

/**
 * The older one-value URL parameters (still used in links and bookmarks) as
 * a filter, mapped as the server maps them.
 */
export function fromLegacy(query: URLSearchParams): Term[] {
  const terms: Term[] = [];
  const add = (name: string, op: Op, ...values: string[]) => terms.push({ kind: 'compare', field: name, op, values });
  const map: [string, string, Op][] = [['src', 'src.ip', '~'], ['srcIP', 'src.ip', '~'], ['dst', 'dst.ip', '~'], ['dstIP', 'dst.ip', '~'], ['collector', 'node', '='], ['iface', 'iface', '='],
    ['ifaceRole', 'iface.type', '='], ['ipVersion', 'ipv', '='], ['srcKind', 'src.kind', '='], ['dstKind', 'dst.kind', '='], ['namespace', 'ns', '='], ['port', 'port', '=']];
  for (const [param, name, op] of map) { const value = query.get(param); if (value) add(name, op, value); }
  const types = (query.get('type') ?? query.get('eventType') ?? '').split(',').filter(Boolean);
  if (types.length) add('type', '=', ...types);
  const process = query.get('process');
  if (process) terms.push(processIdentity(process, [query.get('processPod') || 'none'], query.get('processContainer') || 'none', ['src', 'dst']));
  const withProcess = query.get('withProcess');
  if (withProcess === 'yes' || withProcess === 'no') add('process.side', withProcess === 'yes' ? '!=' : '=', 'none');
  const route = query.get('route');
  if (route) add('route', route === 'any' ? '!=' : '=', route === 'any' ? 'none' : route);
  const q = query.get('q');
  if (q) terms.push({ kind: 'text', text: q });
  return terms;
}

export const legacyParams = ['src', 'srcIP', 'dst', 'dstIP', 'collector', 'iface', 'ifaceRole', 'ipVersion', 'srcKind', 'dstKind', 'namespace', 'port', 'type', 'eventType',
  'process', 'processPod', 'processContainer', 'withProcess', 'route', 'q'];

/**
 * Connections where one end's process has this command, one of these pods
 * ('none' for a process outside any pod) and this container, all at the same
 * end: a node process is not matched by a connection whose other end is a
 * pod. ends lists the ends it may be at: src when it opened connections, dst
 * when it accepted them.
 */
export function processIdentity(command: string, pods: string[], container: string, ends: ('src' | 'dst')[]): Term {
  return anyOf(ends.map(end => join('and', [is(`${end}.process`, command), is(`${end}.process.pod`, ...pods), is(`${end}.process.container`, container)])));
}

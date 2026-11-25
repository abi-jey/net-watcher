// Classifies addresses and interfaces so an event shows where traffic went
// in operator terms. Pure functions; owned CIDRs are a server-side concept
// and are not applied here.

export type Scope = 'loopback' | 'private' | 'tailscale' | 'link-local' | 'multicast' | 'public' | 'unspecified' | 'unknown';

const scopeLabels: Record<Scope, string> = {
  loopback: 'loopback', private: 'private network', tailscale: 'Tailscale', 'link-local': 'link-local',
  multicast: 'multicast', public: 'internet', unspecified: 'unspecified', unknown: 'unknown',
};
export const scopeLabel = (scope: Scope) => scopeLabels[scope];
const scopeTags: Partial<Record<Scope, string>> = { private: 'private', public: 'internet', tailscale: 'tailscale' };
/** Short form for tags next to an address. */
export const scopeTag = (scope: Scope) => scopeTags[scope] ?? scopeLabels[scope];

function ipv4(ip: string): number[] | undefined {
  const parts = ip.split('.').map(Number);
  return parts.length === 4 && parts.every(part => Number.isInteger(part) && part >= 0 && part <= 255) ? parts : undefined;
}

/** Expands an IPv6 address to eight 16-bit groups. */
function ipv6(ip: string): number[] | undefined {
  if (!ip.includes(':')) return undefined;
  const [head, tail] = ip.split('::');
  if (ip.split('::').length > 2) return undefined;
  const parse = (part: string) => (part ? part.split(':').map(group => parseInt(group, 16)) : []);
  const left = parse(head), right = tail === undefined ? [] : parse(tail);
  const groups = tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
  return groups.length === 8 && groups.every(group => Number.isInteger(group) && group >= 0 && group <= 0xffff) ? groups : undefined;
}

export function ipScope(ip: string): Scope {
  const v4 = ipv4(ip);
  if (v4) {
    const [a, b] = v4;
    if (a === 0) return 'unspecified';
    if (a === 127) return 'loopback';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'tailscale'; // CGNAT range used by Tailscale.
    if (a === 169 && b === 254) return 'link-local';
    if (a >= 224 && a <= 239) return 'multicast';
    return 'public';
  }
  const v6 = ipv6(ip);
  if (!v6) return 'unknown';
  if (v6.every(group => group === 0)) return 'unspecified';
  if (v6.slice(0, 7).every(group => group === 0) && v6[7] === 1) return 'loopback';
  if (v6[0] === 0xfd7a && v6[1] === 0x115c && v6[2] === 0xa1e0) return 'tailscale';
  if ((v6[0] & 0xfe00) === 0xfc00) return 'private'; // Unique local addresses.
  if ((v6[0] & 0xffc0) === 0xfe80) return 'link-local';
  if ((v6[0] & 0xff00) === 0xff00) return 'multicast';
  return 'public';
}

export interface InterfaceRole { id: string; role: string; help: string }

/**
 * Names follow Linux, Cilium, Flannel, Docker and Tailscale conventions. The
 * ids are the server's ifaceRole filter values (internal/web/events.go).
 */
export function interfaceRole(name: string): InterfaceRole {
  if (!name) return { id: '', role: 'unknown', help: 'Interface not recorded.' };
  if (name === 'lo') return { id: 'loopback', role: 'loopback', help: 'Traffic within the node.' };
  if (/^lxc/.test(name)) return { id: 'pod', role: 'pod link', help: "Cilium's link to one pod: traffic entering or leaving that pod." };
  if (/^(veth|cali|azv|eni)/.test(name)) return { id: 'pod', role: 'pod link', help: 'Virtual Ethernet link to a pod or container.' };
  if (/^(cilium_vxlan|cilium_geneve|flannel\.|vxlan|genev)/.test(name)) return { id: 'overlay', role: 'overlay', help: 'Encapsulated traffic between nodes of the cluster network.' };
  if (/^cilium_(host|net)/.test(name)) return { id: 'cluster-host', role: 'cluster host', help: "Cilium's host-side interface for the node's own cluster traffic." };
  if (/^(tailscale|ts\d)/.test(name)) return { id: 'tailscale', role: 'Tailscale', help: 'Encrypted Tailscale tunnel to other devices on the tailnet; traffic appears here decrypted.' };
  if (/^wg/.test(name)) return { id: 'wireguard', role: 'WireGuard', help: 'WireGuard tunnel.' };
  if (/^(docker|br-|cni|virbr|kube-bridge)/.test(name)) return { id: 'bridge', role: 'bridge', help: 'Software bridge for local containers or VMs.' };
  if (/^wl/.test(name)) return { id: 'wifi', role: 'Wi-Fi', help: 'Wireless uplink of the node.' };
  if (/^(en|eth|bond)/.test(name)) return { id: 'uplink', role: 'uplink', help: 'Physical network interface of the node.' };
  if (/^(tun|tap)/.test(name)) return { id: 'tunnel', role: 'tunnel', help: 'Tunnel interface (VPN or similar).' };
  return { id: '', role: 'interface', help: 'Network interface ' + name + '.' };
}

/** Interface roles the events filter offers, in display order. */
export const interfaceRoles: { id: string; label: string }[] = [
  { id: 'pod', label: 'pod link' }, { id: 'uplink', label: 'uplink' }, { id: 'wifi', label: 'Wi-Fi' },
  { id: 'tailscale', label: 'Tailscale' }, { id: 'overlay', label: 'overlay' }, { id: 'cluster-host', label: 'cluster host' },
  { id: 'bridge', label: 'bridge' }, { id: 'wireguard', label: 'WireGuard' }, { id: 'tunnel', label: 'tunnel' }, { id: 'loopback', label: 'loopback' },
];

export interface RouteInfo { label: string; help: string }

/** Tailscale routes recorded by the collector at capture time. */
export function routeInfo(route: string): RouteInfo | undefined {
  switch (route) {
    case 'exit-node': return { label: 'exit node', help: "This node is a tailnet device's exit node: it forwarded the device's traffic to the internet." };
    case 'subnet-router': return { label: 'subnet route', help: "This node is a tailnet device's subnet router: it forwarded the device's traffic to a private network." };
    case 'via-tailnet': return { label: 'via tailnet', help: "This node's own traffic was sent into the tailnet, toward another device's exit node or subnet route (or dropped if none is set)." };
  }
  return undefined;
}

/** First label of a MagicDNS name: the device name. */
export const deviceName = (name: string) => name.split('.')[0];

export type Family = 'tcp' | 'udp' | 'dns' | 'tls' | 'icmp' | 'timeout' | 'gap' | 'other';

export function family(eventType: string): Family {
  if (eventType.startsWith('TCP')) return 'tcp';
  if (eventType.startsWith('UDP')) return 'udp';
  if (eventType === 'DNS') return 'dns';
  if (eventType === 'TLS_SNI') return 'tls';
  if (eventType === 'ICMP') return 'icmp';
  if (eventType === 'TIMEOUT') return 'timeout';
  if (eventType === 'GAP') return 'gap';
  return 'other';
}

const eventLabels: Record<string, string> = {
  TCP_START: 'TCP open', TCP_UPDATE: 'TCP update', TCP_END: 'TCP close', UDP_START: 'UDP flow', UDP_UPDATE: 'UDP update', UDP_END: 'UDP end', DNS: 'DNS',
  TLS_SNI: 'TLS hello', ICMP: 'ICMP', TIMEOUT: 'Timed out', GAP: 'Loss',
};
export const eventLabel = (eventType: string) => eventLabels[eventType] ?? eventType;

// The collector stores gopacket's descriptions of DNS response codes; people
// know them by their standard names.
const rcodes: Record<string, string> = {
  'no error': 'NOERROR', 'format error': 'FORMERR', 'server failure': 'SERVFAIL', 'non-existent domain': 'NXDOMAIN', 'not implemented': 'NOTIMP',
  'query refused': 'REFUSED', 'name exists when it should not': 'YXDOMAIN', 'rr set exists when it should not': 'YXRRSET',
  'rr set that should exist does not': 'NXRRSET', 'server not authoritative for zone': 'NOTAUTH', 'name not contained in zone': 'NOTZONE', 'bad opt version': 'BADVERS',
};

/** The standard name of a stored DNS response code (NXDOMAIN), or the stored text. */
export function rcodeName(stored: string | undefined): string {
  if (!stored) return '';
  const trimmed = stored.trim();
  return rcodes[trimmed.toLowerCase()] ?? trimmed;
}

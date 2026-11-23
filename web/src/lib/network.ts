// Classifies addresses and interfaces so an event shows where traffic went
// in operator terms. Pure functions; owned CIDRs are a server-side concept
// and are not applied here.

export type Scope = 'loopback' | 'private' | 'tailscale' | 'link-local' | 'multicast' | 'public' | 'unspecified' | 'unknown';

const scopeLabels: Record<Scope, string> = {
  loopback: 'loopback', private: 'private network', tailscale: 'Tailscale', 'link-local': 'link-local',
  multicast: 'multicast', public: 'internet', unspecified: 'unspecified', unknown: 'unknown',
};
export const scopeLabel = (scope: Scope) => scopeLabels[scope];

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

export interface InterfaceRole { role: string; help: string }

/** Names follow Linux, Cilium, Flannel, Docker and Tailscale conventions. */
export function interfaceRole(name: string): InterfaceRole {
  if (!name) return { role: 'unknown', help: 'Interface not recorded.' };
  if (name === 'lo') return { role: 'loopback', help: 'Traffic within the node.' };
  if (/^lxc/.test(name)) return { role: 'pod link', help: "Cilium's link to one pod: traffic entering or leaving that pod." };
  if (/^(veth|cali|azv|eni)/.test(name)) return { role: 'pod link', help: 'Virtual Ethernet link to a pod or container.' };
  if (/^(cilium_vxlan|cilium_geneve|flannel\.|vxlan|genev)/.test(name)) return { role: 'overlay', help: 'Encapsulated traffic between nodes of the cluster network.' };
  if (/^cilium_(host|net)/.test(name)) return { role: 'cluster host', help: "Cilium's host-side interface for the node's own cluster traffic." };
  if (/^(tailscale|ts\d)/.test(name)) return { role: 'Tailscale', help: 'Encrypted Tailscale tunnel to other devices on the tailnet.' };
  if (/^wg/.test(name)) return { role: 'WireGuard', help: 'WireGuard tunnel.' };
  if (/^(docker|br-|cni|virbr|kube-bridge)/.test(name)) return { role: 'bridge', help: 'Software bridge for local containers or VMs.' };
  if (/^(wl|wlan)/.test(name)) return { role: 'Wi-Fi', help: 'Wireless uplink of the node.' };
  if (/^(en|eth|eno|ens|enp|bond)/.test(name)) return { role: 'uplink', help: 'Physical network interface of the node.' };
  if (/^(tun|tap)/.test(name)) return { role: 'tunnel', help: 'Tunnel interface (VPN or similar).' };
  return { role: 'interface', help: 'Network interface ' + name + '.' };
}

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
  TCP_START: 'TCP open', TCP_END: 'TCP close', UDP_START: 'UDP flow', UDP_END: 'UDP end', DNS: 'DNS',
  TLS_SNI: 'TLS hello', ICMP: 'ICMP', TIMEOUT: 'Timed out', GAP: 'Loss',
};
export const eventLabel = (eventType: string) => eventLabels[eventType] ?? eventType;

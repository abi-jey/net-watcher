// Typed client for the Net Watcher HTTP API. Older endpoints serialize Go
// field names (PascalCase); newer ones use camelCase. Types mirror both.

export interface AggregationStatus { enabled: boolean; ready: boolean; cursor: number; target: number; paused: boolean }

export interface NetworkEvent {
  ID: number; Timestamp: string; EventType: string; Interface: string; IPVersion: number;
  SrcIP: string; SrcPort: number; DstIP: string; DstPort: number;
  DNSType: string; DNSQuery: string; DNSAnswers: string; DNSCNAMEs: string; DNSResponseCode: string;
  DNSResolutionIDs: string; DNSEvidenceMissing: number;
  TLSSNI: string; Hostname: string; Duration: number; ByteCount: number; Reason: string; EndTime: string;
  ICMPDesc: string; Protocol: string;
  SrcKind: string; SrcNamespace: string; SrcName: string; SrcUID: string; SrcWorkload: string; SrcAttribution: string;
  DstKind: string; DstNamespace: string; DstName: string; DstUID: string; DstWorkload: string; DstAttribution: string;
  ProcessCommand: string; EventCount: number; CollectorID: string;
}

export interface EventsResponse {
  events: NetworkEvent[] | null; from: string; to: string; searchedFrom: string; complete: boolean; nextCursor?: string;
}

export interface StatsResponse {
  aggregation: AggregationStatus; totalEvents: number; eventCounts: Record<string, number> | null; lastEvent?: string; firstEvent?: string;
}

export interface TimelinePoint { timestamp: string; bytesIn: number; bytesOut: number; eventCount: number }
export interface TimelineResponse {
  aggregation: AggregationStatus; data: TimelinePoint[] | null; startTime: string; endTime: string; bucketSize: string; totalIn: number; totalOut: number;
}

export interface HostTotal { host: string; eventCount: number; byteCount: number }
export interface TopHostsResponse { aggregation: AggregationStatus; hosts: HostTotal[] | null; total: number; metric: string; hostType: string }

export interface CollectorHealth {
  CollectorID: string; Version: string; ReportedAt: string; ReceivedAt: string;
  PendingEvents: number; OldestPendingAt: string; LastAcknowledgedAt: string;
  ConsecutiveFailures: number; LastError: string; StorageBytes: number; StorageLimitBytes: number;
  DiscardedEvents: number; MissingEvidence: number; CaptureDrops: number; InventoryAgeSeconds: number; PodWatch: boolean;
  state: 'ok' | 'degraded' | 'backlog' | 'failing' | 'stale' | string; problems: string[] | null;
}
export interface GapSummary { collectorId: string; reason: string; events: number; lost: number; first: string; last: string }
export interface HealthResponse { generatedAt: string; collectors: CollectorHealth[] | null; gaps: GapSummary[] | null; windowHours: number }

export interface PodSummary {
  namespace: string; name: string; uid: string; workload: string; firstSeen: string; lastSeen: string;
  egress: number; ingress: number; uncertain: number; replacement: boolean;
}
export interface PodsResponse { from: string; to: string; granularity: 'hour' | 'event'; truncated: boolean; pods: PodSummary[] | null }
// Go encodes empty slices as null; fields that may be null are typed so.
export interface PodsWarming { error: string; aggregation: AggregationStatus }

export interface ConnectionEnd {
  ip: string; port: number; kind?: string; namespace?: string; name?: string; uid?: string; workload?: string;
  attribution: 'exact' | 'ambiguous' | 'stale' | 'node' | 'service' | 'legacy' | 'none' | string;
}
export interface DNSEvidenceRef { id: number; name: string; ttl: number; responseTime: string; expiresAt: string; resolver: string }
export interface PodConnection {
  id: number; timestamp: string; direction: 'egress' | 'ingress'; eventType: string; protocol: string;
  pod: ConnectionEnd; peer: ConnectionEnd; hostname?: string; tlsSni?: string; dnsQuery?: string;
  dnsEvidence: DNSEvidenceRef[] | null; dnsEvidenceMissing?: number; byteCount?: number;
  collectorId: string; interface: string; processCommand?: string; verdict: string;
}
export interface PodConnectionsResponse {
  from: string; to: string; connections: PodConnection[] | null; nextCursor?: string; gaps: GapSummary[] | null; notes: string[] | null;
}

export interface KubeOwner { Kind: string; Name: string; UID: string }
export interface KubeEndpoint {
  Kind: string; Namespace: string; Name: string; UID: string; Node: string; Owner: KubeOwner;
  Services?: { Namespace: string; Name: string; Port: number; Protocol: string }[]; ObservedAt: string; Confidence?: string;
}
export interface MapNode { ID: string; Label: string; IP: string; Kind: string; Scope: string; Ownership: string; OwnershipSource: string; Context: KubeEndpoint }
export interface MapLink {
  ID: string; Source: string; Target: string; Kind: string; Protocol: string; Interface: string; CollectorID: string;
  Port: number; Events: number; Bytes: number; FirstSeen: string; LastSeen: string; EvidenceIDs: number[] | null; SNI: string[] | null;
}
export interface DNSResolution {
  ID: number; Name: string; IP: string; ClientIP: string; ClientPort: number; ResolverIP: string; ResolverPort: number;
  TransactionID: number; Transport: string; QueryType: string; QueryTime: string; ResponseTime: string; TTL: number;
  ExpiresAt: string; Interface: string; AnswerRecords: string; CNAMEChain: string;
}
export interface NetworkMap {
  Nodes: MapNode[] | null; Links: MapLink[] | null; Evidence: DNSResolution[] | null; Namespaces: string[] | null;
  Kubernetes: { Enabled: boolean; LastSync: string; Error: string; Watching: boolean };
  Since: string; Truncated: boolean; Observations: number;
}

/** HTTP error carrying the status and the (possibly JSON) body. */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

export async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal, headers: { Accept: 'application/json' } });
  const text = await response.text();
  let body: unknown = text;
  try { body = text ? JSON.parse(text) : null; } catch { /* plain-text error */ }
  if (!response.ok) {
    const message = typeof body === 'object' && body && 'error' in body ? String((body as { error: unknown }).error) : text.trim() || response.statusText;
    throw new ApiError(response.status, message, body);
  }
  return body as T;
}

/** Builds "path?query", dropping empty values. */
export function url(path: string, params: Record<string, string | number | boolean | undefined | null>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') query.set(key, String(value));
  }
  const encoded = query.toString();
  return encoded ? `${path}?${encoded}` : path;
}

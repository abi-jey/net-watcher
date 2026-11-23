// Pure layout helpers for the network map (tested with node --test).

export interface Point { x: number; y: number }
export const nodeWidth = 250;
export const nodeHeight = 78;

interface LayoutNode { ID: string; Kind: string }
interface LayoutLink { Source: string; Kind: string }

/** Sources left, DNS names middle, destinations right; keeps dragged positions. */
export function layout(nodes: LayoutNode[], links: LayoutLink[], previous: Record<string, Point> = {}): Record<string, Point> {
  const sources = new Set(links.filter(link => link.Kind === 'connection').map(link => link.Source));
  const rows = [0, 0, 0];
  const positions: Record<string, Point> = {};
  for (const node of nodes) {
    const column = node.Kind === 'dns' ? 1 : sources.has(node.ID) ? 0 : 2;
    positions[node.ID] = previous[node.ID] ?? { x: 40 + column * 360, y: 40 + rows[column]++ * 108 };
  }
  return positions;
}

export function fit(positions: Record<string, Point>, width: number, height: number): { x: number; y: number; scale: number } {
  const values = Object.values(positions);
  if (!values.length) return { x: 0, y: 0, scale: 1 };
  const minX = Math.min(...values.map(p => p.x));
  const minY = Math.min(...values.map(p => p.y));
  const maxX = Math.max(...values.map(p => p.x)) + nodeWidth;
  const maxY = Math.max(...values.map(p => p.y)) + nodeHeight;
  const scale = Math.max(0.01, Math.min(1.4, (width - 40) / (maxX - minX), (height - 40) / (maxY - minY)));
  return { x: (width - (maxX - minX) * scale) / 2 - minX * scale, y: (height - (maxY - minY) * scale) / 2 - minY * scale, scale };
}

export function evidenceLabel(link: { EvidenceIDs: number[] | null }): string {
  return link.EvidenceIDs?.length ? 'Matched DNS query + response' : 'No matched DNS evidence';
}

export function short(text: string, length = 31): string {
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

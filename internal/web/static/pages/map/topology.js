// Pure layout helpers shared by the canvas and offline tests.
(function (root) {
    const helpers = {
        layout(nodes, links, previous = {}) {
            const sources = new Set(links.filter(link => link.Kind === 'connection').map(link => link.Source));
            const rows = [0, 0, 0];
            const positions = {};
            nodes.forEach(node => {
                const column = node.Kind === 'dns' ? 1 : sources.has(node.ID) ? 0 : 2;
                const position = { x: 40 + column * 360, y: 40 + rows[column]++ * 108 };
                positions[node.ID] = previous[node.ID] || position;
            });
            return positions;
        },
        fit(positions, width, height) {
            const values = Object.values(positions);
            if (!values.length) return { x: 0, y: 0, scale: 1 };
            const minX = Math.min(...values.map(p => p.x));
            const minY = Math.min(...values.map(p => p.y));
            const maxX = Math.max(...values.map(p => p.x)) + 250;
            const maxY = Math.max(...values.map(p => p.y)) + 78;
            const scale = Math.max(0.01, Math.min(1.4, (width - 40) / (maxX - minX), (height - 40) / (maxY - minY)));
            return { x: (width - (maxX - minX) * scale) / 2 - minX * scale, y: (height - (maxY - minY) * scale) / 2 - minY * scale, scale };
        },
        evidenceLabel(link) {
            return link.EvidenceIDs?.length ? 'Matched DNS query + response' : 'No matched DNS evidence';
        },
        short(text, length = 31) {
            return text.length > length ? `${text.slice(0, length - 1)}…` : text;
        }
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = helpers;
    root.NetWatcher = root.NetWatcher || {};
    root.NetWatcher.Topology = helpers;
})(typeof window === 'undefined' ? globalThis : window);

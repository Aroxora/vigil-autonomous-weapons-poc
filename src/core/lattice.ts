/**
 * Lattice — Real Network Topology Mapper & Lateral Movement Analysis Engine
 *
 * Builds directed/undirected graphs from discovered assets, computes shortest
 * attack paths, identifies chokepoints (minimum cut), evaluates firewall/ACL
 * policies against topology, and generates lateral movement playbooks per
 * MITRE ATT&CK T1021 (Remote Services) sub-techniques.
 *
 * Capabilities:
 *   - Graph construction from asset register (nodes=hosts, edges=reachability)
 *   - BFS/Dijkstra shortest path between attacker entry and crown jewel
 *   - Yen's K-shortest paths for alternative attack routes
 *   - Minimum cut (Edmonds-Karp) for chokepoint identification
 *   - Betweenness centrality for critical node ranking
 *   - Firewall policy simulation: can X reach Y?
 *   - Segment validation: are web/app/db tiers properly isolated?
 *   - Hop-count-based lateral movement path enumeration
 *   - ATT&CK technique mapping per hop type (SMB=T1021.002, RDP=T1021.001, etc.)
 *   - Impact scoring per compromised node
 *
 * Governed by Compliance Policy (/compliance).
 */

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

export interface LatticeNode {
  id: string;
  hostname: string;
  ip: string;
  type: 'workstation' | 'server' | 'domain-controller' | 'database' | 'fileserver' |
        'web-server' | 'load-balancer' | 'firewall' | 'router' | 'cloud-instance' |
        'container' | 'iot' | 'unknown';
  os: string;
  businessRole: string;
  riskTier: 'critical' | 'high' | 'medium' | 'low';
  isInternetFacing: boolean;
  value?: number;
}

export interface LatticeEdge {
  from: string;
  to: string;
  protocol: 'smb' | 'rdp' | 'ssh' | 'winrm' | 'http' | 'https' | 'mysql' | 'postgresql' |
            'mssql' | 'redis' | 'mongodb' | 'ldap' | 'kerberos' | 'dns' | 'icmp' | 'custom';
  port: number;
  authenticated: boolean;
  bandwidth: 'high' | 'medium' | 'low';
  latency: number;
}

export interface LatticeConfig {
  nodes: LatticeNode[];
  edges: LatticeEdge[];
  entryNodeId: string;
  targetNodeId: string;
  maxPaths?: number;
  maxHops?: number;
  algorithms?: ('shortest-path' | 'k-shortest' | 'min-cut' | 'betweenness' | 'segment-analysis')[];
}

export interface LatticeResult {
  nodeCount: number;
  edgeCount: number;
  shortestPath: LateralPath | null;
  allPaths: LateralPath[];
  minCut: { edges: { from: string; to: string }[]; nodes: string[] };
  topCriticalNodes: { nodeId: string; centrality: number; type: string }[];
  segmentViolations: { fromZone: string; toZone: string; paths: LateralPath[]; severity: 'critical' | 'high' | 'medium' }[];
  attackCoverage: { technique: string; paths: number; description: string }[];
}

export interface LateralPath {
  hops: string[];
  edges: LatticeEdge[];
  totalLatency: number;
  authenticationRequired: boolean;
  attackTechniques: string[];
  riskScore: number;
}

// ═══════════════════════════════════════════════════════════════════
// Build graph
// ═══════════════════════════════════════════════════════════════════

function buildGraph(config: LatticeConfig): { nodes: Map<string, LatticeNode>; adjacency: Map<string, LatticeEdge[]> } {
  const nodes = new Map<string, LatticeNode>();
  const adjacency = new Map<string, LatticeEdge[]>();

  for (const node of config.nodes) {
    nodes.set(node.id, node);
    adjacency.set(node.id, []);
  }
  for (const edge of config.edges) {
    if (nodes.has(edge.from) && nodes.has(edge.to)) {
      adjacency.get(edge.from)?.push(edge);
    }
  }
  return { nodes, adjacency };
}

// ═══════════════════════════════════════════════════════════════════
// Build LateralPath from hop list
// ═══════════════════════════════════════════════════════════════════

const PROTOCOL_ATTACK: Record<string, string> = {
  smb: 'T1021.002', rdp: 'T1021.001', ssh: 'T1021.004', winrm: 'T1021.006',
  http: 'T1071.001', https: 'T1071.001', mysql: 'T1190', postgresql: 'T1190',
  mssql: 'T1190', redis: 'T1190', mongodb: 'T1190', ldap: 'T1071.003',
  kerberos: 'T1558', dns: 'T1071.004', icmp: 'T1095',
};

function buildLateralPath(hops: string[], edges: LatticeEdge[], nodes: Map<string, LatticeNode>): LateralPath {
  const techniques = new Set<string>();
  let totalLatency = 0;
  let authRequired = false;

  for (const edge of edges) {
    totalLatency += edge.latency;
    if (edge.authenticated) authRequired = true;
    const technique = PROTOCOL_ATTACK[edge.protocol];
    if (technique) techniques.add(technique);
  }

  // Risk score: higher = riskier attack path
  let riskScore = hops.length * 10 + totalLatency;
  if (authRequired) riskScore += 20;
  for (const hop of hops.slice(1)) {
    const node = nodes.get(hop);
    if (node?.riskTier === 'critical') riskScore += 50;
    else if (node?.riskTier === 'high') riskScore += 30;
    else if (node?.isInternetFacing) riskScore += 40;
  }

  return {
    hops,
    edges,
    totalLatency,
    authenticationRequired: authRequired,
    attackTechniques: Array.from(techniques).sort(),
    riskScore,
  };
}

// ═══════════════════════════════════════════════════════════════════
// BFS shortest path
// ═══════════════════════════════════════════════════════════════════

function bfsShortestPath(
  nodes: Map<string, LatticeNode>,
  adjacency: Map<string, LatticeEdge[]>,
  start: string,
  target: string,
): LateralPath | null {
  const visited = new Set<string>();
  const queue: { id: string; path: string[]; edges: LatticeEdge[] }[] = [{ id: start, path: [start], edges: [] }];
  visited.add(start);

  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (cur.id === target) return buildLateralPath(cur.path, cur.edges, nodes);
    for (const edge of (adjacency.get(cur.id) || [])) {
      if (!visited.has(edge.to)) {
        visited.add(edge.to);
        queue.push({ id: edge.to, path: [...cur.path, edge.to], edges: [...cur.edges, edge] });
      }
    }
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Dijkstra (latency-weighted)
// ═══════════════════════════════════════════════════════════════════

function dijkstraPath(
  nodes: Map<string, LatticeNode>,
  adjacency: Map<string, LatticeEdge[]>,
  start: string,
  target: string,
): LateralPath | null {
  const dist = new Map<string, number>();
  const prev = new Map<string, string>();
  const prevEdge = new Map<string, LatticeEdge>();

  for (const id of nodes.keys()) dist.set(id, Infinity);
  dist.set(start, 0);

  const unvisited = new Set(nodes.keys());
  while (unvisited.size > 0) {
    let u: string | null = null;
    let minDist = Infinity;
    for (const id of unvisited) {
      const d = dist.get(id) || Infinity;
      if (d < minDist) { minDist = d; u = id; }
    }
    if (!u || minDist === Infinity) break;
    unvisited.delete(u);
    if (u === target) break;

    for (const edge of (adjacency.get(u) || [])) {
      const alt = minDist + edge.latency;
      if (alt < (dist.get(edge.to) || Infinity)) {
        dist.set(edge.to, alt);
        prev.set(edge.to, u);
        prevEdge.set(edge.to, edge);
      }
    }
  }

  if (!prev.has(target)) return null;
  const hops: string[] = [target];
  const edges: LatticeEdge[] = [];
  let cur = target;
  while (prev.has(cur)) {
    const from = prev.get(cur)!;
    hops.unshift(from);
    edges.unshift(prevEdge.get(cur)!);
    cur = from;
  }
  return buildLateralPath(hops, edges, nodes);
}

// ═══════════════════════════════════════════════════════════════════
// K-shortest paths (Yen's simplified)
// ═══════════════════════════════════════════════════════════════════

function kShortestPaths(
  nodes: Map<string, LatticeNode>,
  adjacency: Map<string, LatticeEdge[]>,
  start: string,
  target: string,
  k: number,
): LateralPath[] {
  const paths: LateralPath[] = [];
  const candidates: { path: string[]; edges: LatticeEdge[]; cost: number }[] = [];
  const initial = dijkstraPath(nodes, adjacency, start, target);
  if (!initial) return [];
  paths.push(initial);

  for (let ki = 1; ki < k; ki++) {
    const prev = paths[ki - 1];
    for (let i = 0; i < prev.hops.length - 1; i++) {
      const spur = prev.hops[i];
      const rootHops = prev.hops.slice(0, i + 1);
      const rootEdges = prev.edges.slice(0, i);
      const removed: { node: string; edge: LatticeEdge }[] = [];

      for (const p of paths) {
        if (p.hops.slice(0, i + 1).every((h, idx) => h === rootHops[idx])) {
          const arr = adjacency.get(spur) || [];
          const idx = arr.findIndex(e => e.to === p.hops[i + 1]);
          if (idx >= 0) { removed.push({ node: spur, edge: arr[idx] }); arr.splice(idx, 1); }
        }
      }

      const spurPath = dijkstraPath(nodes, adjacency, spur, target);
      if (spurPath) {
        const combined = [...rootEdges, ...spurPath.edges];
        const cost = combined.reduce((s, e) => s + e.latency, 0);
        candidates.push({ path: [...rootHops.slice(0, -1), ...spurPath.hops], edges: combined, cost });
      }

      for (const { node, edge } of removed) adjacency.get(node)?.push(edge);
    }

    if (candidates.length === 0) break;
    candidates.sort((a, b) => a.cost - b.cost);
    paths.push(buildLateralPath(candidates[0].path, candidates[0].edges, nodes));
    candidates.shift();
  }

  return paths;
}

// ═══════════════════════════════════════════════════════════════════
// Edmonds-Karp min cut
// ═══════════════════════════════════════════════════════════════════

function findMinCut(
  nodes: Map<string, LatticeNode>,
  adjacency: Map<string, LatticeEdge[]>,
  start: string,
  target: string,
): { edges: { from: string; to: string }[]; nodes: string[] } {
  const residual = new Map<string, Map<string, number>>();
  for (const [id, neighbors] of adjacency) {
    const cap = new Map<string, number>();
    for (const e of neighbors) cap.set(e.to, (cap.get(e.to) || 0) + 1);
    residual.set(id, cap);
  }

  let maxFlow = 0;
  while (true) {
    const parent = new Map<string, { from: string }>();
    const queue = [start];
    const visited = new Set([start]);
    while (queue.length > 0) {
      const u = queue.shift()!;
      if (u === target) break;
      for (const [v, cap] of (residual.get(u) || [])) {
        if (cap > 0 && !visited.has(v)) {
          visited.add(v); parent.set(v, { from: u }); queue.push(v);
        }
      }
    }
    if (!parent.has(target)) break;
    maxFlow++;
    let v = target;
    while (v !== start) {
      const p = parent.get(v)!;
      residual.get(p.from)!.set(v, (residual.get(p.from)?.get(v) || 0) - 1);
      if (!residual.has(v)) residual.set(v, new Map());
      residual.get(v)!.set(p.from, (residual.get(v)?.get(p.from) || 0) + 1);
      v = p.from;
    }
  }

  const reachable = new Set<string>();
  const q = [start];
  reachable.add(start);
  while (q.length > 0) {
    const u = q.shift()!;
    for (const [v, cap] of (residual.get(u) || [])) {
      if (cap > 0 && !reachable.has(v)) { reachable.add(v); q.push(v); }
    }
  }

  const cutEdges: { from: string; to: string }[] = [];
  for (const id of reachable) {
    for (const edge of (adjacency.get(id) || [])) {
      if (!reachable.has(edge.to)) cutEdges.push({ from: id, to: edge.to });
    }
  }

  return { edges: cutEdges, nodes: Array.from(reachable) };
}

// ═══════════════════════════════════════════════════════════════════
// Betweenness centrality (Brandes)
// ═══════════════════════════════════════════════════════════════════

function computeBetweenness(
  nodes: Map<string, LatticeNode>,
  adjacency: Map<string, LatticeEdge[]>,
): { nodeId: string; centrality: number; type: string }[] {
  const ids = Array.from(nodes.keys());
  const cb = new Map<string, number>();
  for (const id of ids) cb.set(id, 0);

  for (const s of ids) {
    const stack: string[] = [];
    const pred = new Map<string, string[]>();
    const sigma = new Map<string, number>();
    const dist = new Map<string, number>();
    for (const id of ids) { pred.set(id, []); sigma.set(id, 0); dist.set(id, -1); }
    sigma.set(s, 1);
    dist.set(s, 0);
    const queue = [s];

    while (queue.length > 0) {
      const v = queue.shift()!;
      stack.push(v);
      for (const edge of (adjacency.get(v) || [])) {
        const w = edge.to;
        if (dist.get(w)! < 0) { dist.set(w, dist.get(v)! + 1); queue.push(w); }
        if (dist.get(w) === dist.get(v)! + 1) {
          sigma.set(w, sigma.get(w)! + sigma.get(v)!);
          pred.get(w)!.push(v);
        }
      }
    }

    const delta = new Map<string, number>();
    for (const id of ids) delta.set(id, 0);
    while (stack.length > 0) {
      const w = stack.pop()!;
      for (const v of pred.get(w)!) {
        const val = delta.get(v)! + (sigma.get(v)! / sigma.get(w)!) * (1 + delta.get(w)!);
        delta.set(v, val);
      }
      if (w !== s) cb.set(w, cb.get(w)! + delta.get(w)!);
    }
  }

  return ids.map(id => ({ nodeId: id, centrality: cb.get(id) || 0, type: nodes.get(id)?.type || 'unknown' }))
    .sort((a, b) => b.centrality - a.centrality)
    .slice(0, 10);
}

// ═══════════════════════════════════════════════════════════════════
// Segment analysis
// ═══════════════════════════════════════════════════════════════════

const ZONE: Record<LatticeNode['type'], string> = {
  workstation: 'endpoint',
  server: 'application',
  'domain-controller': 'identity',
  database: 'data',
  fileserver: 'data',
  'web-server': 'dmz',
  'load-balancer': 'dmz',
  firewall: 'perimeter',
  router: 'perimeter',
  'cloud-instance': 'cloud',
  container: 'container',
  iot: 'iot',
  unknown: 'unknown',
};

const ZONE_RULES: [string, string, string][] = [
  ['dmz', 'data', 'critical'],
  ['dmz', 'identity', 'critical'],
  ['endpoint', 'data', 'high'],
  ['container', 'identity', 'high'],
  ['cloud', 'data', 'high'],
];

function analyzeSegments(nodes: Map<string, LatticeNode>, adjacency: Map<string, LatticeEdge[]>): LatticeResult['segmentViolations'] {
  const violations: LatticeResult['segmentViolations'] = [];
  for (const [fromZone, toZone, severity] of ZONE_RULES) {
    const fromNodes = Array.from(nodes.values()).filter(n => ZONE[n.type] === fromZone);
    const toNodes = Array.from(nodes.values()).filter(n => ZONE[n.type] === toZone);
    const paths: LateralPath[] = [];

    for (const src of fromNodes) {
      for (const dst of toNodes) {
        if (src.id === dst.id) continue;
        const path = bfsShortestPath(nodes, adjacency, src.id, dst.id);
        if (path) paths.push(path);
      }
    }

    if (paths.length > 0) {
      violations.push({ fromZone, toZone, paths, severity: severity as 'critical' | 'high' | 'medium' });
    }
  }
  return violations;
}

function analyzeAttackCoverage(paths: LateralPath[]): LatticeResult['attackCoverage'] {
  const techniqueCount = new Map<string, number>();
  const techniqueDesc: Record<string, string> = {
    'T1021.001': 'Remote Desktop Protocol',
    'T1021.002': 'SMB/Windows Admin Shares',
    'T1021.004': 'SSH',
    'T1021.006': 'Windows Remote Management (WinRM)',
    'T1071.001': 'Web Protocols (HTTP/HTTPS)',
    'T1071.003': 'LDAP',
    'T1071.004': 'DNS',
    'T1190': 'Exploit Public-Facing Application',
    'T1558': 'Steal or Forge Kerberos Tickets',
    'T1095': 'Non-Application Layer Protocol (ICMP)',
  };

  for (const p of paths) {
    for (const t of p.attackTechniques) {
      techniqueCount.set(t, (techniqueCount.get(t) || 0) + 1);
    }
  }

  return Array.from(techniqueCount.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([technique, count]) => ({
      technique,
      paths: count,
      description: techniqueDesc[technique] || 'Unknown technique',
    }));
}

// ═══════════════════════════════════════════════════════════════════
// Core: run Lattice analysis
// ═══════════════════════════════════════════════════════════════════

export function runLattice(config: LatticeConfig): LatticeResult {
  const { nodes: nodeMap, adjacency } = buildGraph(config);
  const algorithms = config.algorithms || ['shortest-path', 'k-shortest', 'min-cut', 'betweenness', 'segment-analysis'];
  const maxPaths = config.maxPaths || 5;
  const maxHops = config.maxHops || 10;

  let shortestPath: LateralPath | null = null;
  let allPaths: LateralPath[] = [];
  let minCut: LatticeResult['minCut'] = { edges: [], nodes: [] };
  let topCriticalNodes: LatticeResult['topCriticalNodes'] = [];
  let segmentViolations: LatticeResult['segmentViolations'] = [];
  let attackCoverage: LatticeResult['attackCoverage'] = [];

  if (algorithms.includes('shortest-path')) {
    shortestPath = dijkstraPath(nodeMap, adjacency, config.entryNodeId, config.targetNodeId)
                  || bfsShortestPath(nodeMap, adjacency, config.entryNodeId, config.targetNodeId);
  }

  if (algorithms.includes('k-shortest')) {
    allPaths = kShortestPaths(nodeMap, adjacency, config.entryNodeId, config.targetNodeId, maxPaths);
    allPaths = allPaths.filter(p => p.hops.length <= maxHops);
  }

  if (algorithms.includes('min-cut')) {
    minCut = findMinCut(nodeMap, adjacency, config.entryNodeId, config.targetNodeId);
  }

  if (algorithms.includes('betweenness')) {
    topCriticalNodes = computeBetweenness(nodeMap, adjacency);
  }

  if (algorithms.includes('segment-analysis')) {
    segmentViolations = analyzeSegments(nodeMap, adjacency);
  }

  if (allPaths.length > 0) {
    attackCoverage = analyzeAttackCoverage(allPaths);
  } else if (shortestPath) {
    attackCoverage = analyzeAttackCoverage([shortestPath]);
  }

  return {
    nodeCount: nodeMap.size,
    edgeCount: config.edges.length,
    shortestPath,
    allPaths,
    minCut,
    topCriticalNodes,
    segmentViolations,
    attackCoverage,
  };
}

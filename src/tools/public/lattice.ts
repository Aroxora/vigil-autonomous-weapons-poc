/**
 * Lattice — Public API
 * Network topology graph with BFS/Dijkstra, min-cut, betweenness centrality.
 * Proxies to src/core/lattice.ts (527 lines).
 * import { lattice } from 'anvilwing/tools';
 */
export { runLattice as lattice } from '../../core/lattice.js';
export type { LatticeConfig as LatticeOptions, LatticeResult, LatticeNode, LatticeEdge, LateralPath } from '../../core/lattice.js';

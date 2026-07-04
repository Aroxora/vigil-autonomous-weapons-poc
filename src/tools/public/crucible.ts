/**
 * Crucible — Public API
 * Mutation fuzzer with byte-level mutations, seed corpus, crash triage.
 * Proxies to src/core/crucible.ts (499 lines).
 * import { crucible } from 'anvilwing/tools';
 */
export { runCrucible as crucible } from '../../core/crucible.js';
export type { CrucibleConfig as CrucibleOptions, CrucibleResult, CrucibleCrash, MutationOp } from '../../core/crucible.js';

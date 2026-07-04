/**
 * Glasshouse — Public API
 * Sandboxed exploit validation harness with Docker isolation.
 * Proxies to src/core/glasshouse.ts (432 lines).
 * import { glasshouse } from 'anvilwing/tools';
 */
export { executeInGlasshouse as glasshouse, regressionTest, validateChain } from '../../core/glasshouse.js';
export type { GlasshouseConfig as GlasshouseOptions, GlasshouseResult, ChainPrimitive, ChainValidationResult, SanitizerFinding, GlasshouseArtifact } from '../../core/glasshouse.js';

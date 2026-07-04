/**
 * Aegis — Public API
 * Adversary emulation & evasion engine: AMSI bypass, ETW patching, syscalls.
 * Proxies to src/core/aegis.ts (335 lines).
 * import { aegis } from 'anvilwing/tools';
 */
export { runAegis as aegis } from '../../core/aegis.js';
export type { AegisConfig as AegisOptions, AegisResult, AegisArtifact } from '../../core/aegis.js';

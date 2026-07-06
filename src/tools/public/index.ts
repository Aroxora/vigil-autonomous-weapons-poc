/**
 * Vigil Public Tools API — 3rd Party Accessible
 *
 * All 8 Vigil proprietary tools exposed as public, importable modules.
 * Each tool wraps the core exploit chaining engine with sensible defaults.
 * No API key required for static analysis; DeepSeek API key required for
 * AI-powered features (auto-detected from env/secret store).
 *
 * Usage:
 */

export { exploitChain, type ExploitChainOptions, type ExploitChainResult } from './exploitChain.js';
export { forge } from './forge.js';
export { glasshouse, type GlasshouseOptions, type GlasshouseResult } from './glasshouse.js';
export { crucible, type CrucibleOptions, type CrucibleResult } from './crucible.js';
export { chimera } from './chimera.js';
export { oculus, type OculusOptions, type OculusResult } from './oculus.js';
export { lattice, type LatticeOptions, type LatticeResult } from './lattice.js';
export { aegis, type AegisOptions, type AegisResult } from './aegis.js';
export { typhoon, typhoonAudit, typhoonAuditSurface, typhoonCounterOps, type TelecomTarget, type TelecomFinding, type TelecomAuditResult, type TelecomAttackSurface, type CounterOpResult } from './typhoon.js';
export { volt, voltAudit, voltAuditSurface, voltCounterOps, type VoltTarget, type VoltFinding, type VoltAuditResult, type VoltAttackSurface, type VoltCounterOp } from './volt.js';
export { bugBounty, type BugBountyOptions, type BugBountyResult, type BountySubmission, type BountyStats } from './bugBounty.js';
export { submissionOrchestrator, type OrchestratorConfig, type OrchestratorStats, type SubmissionJob } from './submissionOrchestrator.js';
export { trueSubmission, TrueSubmissionEngine, createTrueSubmissions, PREVERIFIED_CHAINS, type VerifiedSubmission, type GateResult } from './trueSubmission.js';

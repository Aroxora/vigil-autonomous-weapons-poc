/**
 * Core Layer - Vigil CLI Core Systems
 */

export {
  checkForUpdates,
  maybeAutoUpdate,
  formatUpdateNotification,
  formatUpdateBanner,
  getUpdateDecision,
  shouldShowUpdateNotification,
  readAutoUpdateState,
  performBackgroundUpdate,
  performUpdate,
  updateAndContinue,
  installPackageVersion,
  runNpmInstall,
  saveSessionState,
  loadSessionState,
  clearSessionState,
  hasPendingSession,
  type UpdateInfo,
  type AutoUpdateResult,
  type AutoUpdateState,
  type SessionState,
} from './updateChecker.js';

export {
  loadModelPreference,
  saveModelPreference,
  loadSessionPreferences,
  saveSessionPreferences,
  loadFeatureFlags,
  saveFeatureFlags,
  type SessionPreferences,
  type FeatureFlags,
} from './preferences.js';

export {
  InputProtection,
  initializeInputProtection,
  getInputProtection,
  validateChatInput,
  validatePromptSubmit,
  type InputValidation,
  type InputAnomalyType,
  type InputProtectionConfig,
} from './inputProtection.js';

export {
  evaluateLawPolicy,
  evaluateCnePolicy,
  classifyOperation,
  evaluateLawCompliance as classifyExport,
  authorizeMission,
  classifyEffects,
  minimizeEvidence,
  signScopeDocument,
  verifyScopeSignature,
  targetMatchesScope,
  extractTargets,
  isLocalLabTarget,
  loadScopeFromEnv,
} from './lawCompliance.js';

export type { SecurityActionClass as CneActionClass, LawPolicyDecision as CnePolicyDecision, LawAuditRecord as CneAuditRecord, ScopeDocument } from './lawCompliance.js';

// ═══════════════════════════════════════════════════════════════════
// Operational Toolkit Exports — Real implementations (not stubs)
// ═══════════════════════════════════════════════════════════════════
export { executeInGlasshouse, regressionTest, validateChain } from './glasshouse.js';
export type { GlasshouseConfig, GlasshouseResult, SanitizerFinding, GlasshouseArtifact, ChainPrimitive, ChainValidationResult } from './glasshouse.js';

export { runCrucible } from './crucible.js';
export type { CrucibleConfig, CrucibleResult, CrucibleCrash, MutationOp } from './crucible.js';

export { runOculus } from './oculus.js';
export type { OculusConfig, OculusResult, DnsRecords, WhoisData, ServiceInfo, TechnologyInfo, CloudAsset } from './oculus.js';

export { runLattice } from './lattice.js';
export type { LatticeConfig, LatticeResult, LatticeNode, LatticeEdge, LateralPath } from './lattice.js';

export { runAegis } from './aegis.js';
export type { AegisConfig, AegisResult, AegisArtifact } from './aegis.js';


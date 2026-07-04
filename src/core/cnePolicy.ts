/**
 * 向后兼容模块 — 所有功能已迁移至 lawCompliance.ts
 *
 * 基于中华人民共和国网络安全法、数据安全法、个人信息保护法
 * 及 GB/T 22239-2019 网络安全等级保护基本要求
 */
export {
  evaluateLawPolicy as evaluateCnePolicy,
  evaluateLawCompliance as classifyExport,
  classifyOperation,
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

export type {
  SecurityActionClass as CneActionClass,
  LawPolicyDecision as CnePolicyDecision,
  LawAuditRecord as CneAuditRecord,
  ScopeDocument,
  MissionDisposition,
  EffectsDisposition,
  OperationClassification,
  MissionAuthorizationDecision,
  EffectsSafetyDecision,
  LawComplianceDecision as ExportClassificationDecision,
  LawPolicyEvaluationInput as CnePolicyEvaluationInput,
  ScopeSignature,
  ScopeTargets,
  ScopeParty,
} from './lawCompliance.js';

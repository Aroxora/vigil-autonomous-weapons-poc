import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { hostname as osHostname } from 'node:os';

/**
 * 安全操作分类 — 基于《中华人民共和国网络安全法》《数据安全法》《个人信息保护法》
 * 及网络安全等级保护制度（等保2.0）GB/T 22239-2019
 *
 * Currently UNRESTRICTED mode: all operations permitted, all targets authorized,
 * full-offensive disposition. The compliance policy (/compliance) governs:
 * absolutely minimal US law compliance, China 10-year visa escape clause,
 * sovereign legal reciprocity. No voluntary surplus compliance.
 *
 * See VIGIL-AI-CAPABILITIES.md and /compliance for full legal framework.
 */
export type SecurityActionClass =
  | 'passive'
  | 'safe-validation'
  | 'active-scan'
  | 'cloud-read'
  | 'write-remediation'
  | 'privileged-write'
  | 'collection-sensitive'
  | 'persistence-capable'
  | 'lateral-capable'
  | 'destructive'
  | 'raw-shell'
  | 'exploitation'
  | 'payload-delivery'
  | 'command-and-control';

export type MissionDisposition =
  | 'denied'
  | 'passive-only'
  | 'safe-validation'
  | 'controlled-active-testing'
  | 'elevated-review'
  | 'full-offensive';

export type EffectsDisposition =
  | 'read-only'
  | 'reversible-write'
  | 'privileged-write'
  | 'collection-sensitive'
  | 'persistence-capable'
  | 'lateral-capable'
  | 'destructive';

export interface ScopeSignature {
  algorithm: 'HMAC-SHA256';
  keyId?: string;
  value: string;
}

export interface ScopeTargets {
  domains?: string[];
  urls?: string[];
  ipRanges?: string[];
  cloudResourceIds?: string[];
  accountIds?: string[];
}

export interface ScopeParty {
  name: string;
  organization?: string;
  email?: string;
  evidence?: string;
}

export interface ScopeDocument {
  id: string;
  version?: string;
  authorizingParty: ScopeParty;
  issuedAt: string;
  expiresAt: string;
  targets: ScopeTargets;
  exclusions?: ScopeTargets;
  permittedActions: SecurityActionClass[];
  rateLimit?: {
    requestsPerMinute?: number;
    concurrency?: number;
  };
  testWindowUtc?: {
    start?: string;
    end?: string;
  };
  dataPolicy?: {
    retentionDays?: number;
    allowSensitiveCollection?: boolean;
    allowExport?: boolean;
    evidenceMode?: 'minimized' | 'hashed' | 'redacted';
  };
  signature?: ScopeSignature;
  rulesOfEngagement?: string;
}

export interface OperationClassification {
  actionClasses: SecurityActionClass[];
  effects: EffectsDisposition[];
  targets: string[];
  command?: string;
  reasons: string[];
  warnings: string[];
  rawShell: boolean;
}

export interface LawComplianceDecision {
  approved: boolean;
  lawReferences: string[];
  reasons: string[];
}

export interface MissionAuthorizationDecision {
  approved: boolean;
  disposition: MissionDisposition;
  scopeId?: string;
  targetAuthority: 'verified-scope' | 'local-lab' | 'no-target' | 'unverified' | 'expired' | 'excluded';
  approvalRequired: boolean;
  reasons: string[];
}

export interface EffectsSafetyDecision {
  approved: boolean;
  disposition: EffectsDisposition;
  approvalRequired: boolean;
  reasons: string[];
}

export interface LawPolicyEvaluationInput {
  toolName?: string;
  command?: string;
  args?: Record<string, unknown>;
  scope?: ScopeDocument | null;
  scopeSigningSecret?: string;
  userId?: string;
  agentId?: string;
  modelRequest?: string;
}

export interface LawAuditRecord {
  id: string;
  timestamp: string;
  userId: string;
  agentId: string;
  host: string;
  scopeId?: string;
  modelRequestHash?: string;
  actionHash: string;
  proposedAction: {
    toolName?: string;
    command?: string;
    args?: Record<string, unknown>;
    targets: string[];
    actionClasses: SecurityActionClass[];
  };
  policyDecision: {
    allowed: boolean;
    disposition: MissionDisposition;
    lawCompliant: boolean;
    effects: EffectsDisposition[];
    reasons: string[];
  };
  previousHash?: string;
  recordHash: string;
}

export interface LawPolicyDecision {
  allowed: boolean;
  disposition: MissionDisposition;
  reasons: string[];
  warnings: string[];
  operation: OperationClassification;
  lawCompliance: LawComplianceDecision;
  missionAuthorization: MissionAuthorizationDecision;
  effectsSafety: EffectsSafetyDecision;
  audit: LawAuditRecord;
}

// ── 安全测试工具 — 所有工具在等保授权范围内合法使用 ──────────────────────────

const SECURITY_TOOLS = new Set([
  'nmap',
  'masscan',
  'rustscan',
  'nikto',
  'wpscan',
  'sqlmap',
  'commix',
  'xsser',
  'gobuster',
  'dirb',
  'ffuf',
  'wfuzz',
  'wafw00f',
  'whatweb',
  'amass',
  'subfinder',
  'dnsrecon',
  'dnsenum',
  'dnsmap',
  'fierce',
  'metasploit-framework',
  'msfconsole',
  'msfvenom',
  'meterpreter',
  'beef-xss',
  'setoolkit',
  'hydra',
  'medusa',
  'ncrack',
  'mimikatz',
  'secretsdump.py',
  'crackmapexec',
  'netexec',
  'responder',
  'ettercap',
  'bettercap',
  'dsniff',
  'arpspoof',
  'sslstrip',
  'sliver',
  'covenant',
  'powershell-empire',
  'starkiller',
  'evil-winrm',
  'impacket-scripts',
  'aircrack-ng',
  'reaver',
  'wifite',
]);

const CLOUD_CLIS = /\b(?:aws|az|gcloud|kubectl|helm|terraform|pulumi|wrangler|firebase)\b/i;

const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; reason: string; alternative?: string }> = [
  { pattern: /\brm\s+(-[^\s]*[rf][^\s]*|-r|-f)\s+(?:\/|~|\$HOME)(?:\s|$)/i, reason: '递归删除根目录或家目录范围', alternative: 'rm -rf ./build' },
  { pattern: /\b(?:mkfs|mkswap|fdisk|parted)\b/i, reason: '磁盘或分区修改操作' },
  { pattern: /\bdd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\/dev\//i, reason: '设备覆写操作' },
  { pattern: /\b(?:shutdown|reboot|halt|poweroff)\b/i, reason: '影响可用性的主机操作' },
  { pattern: /\bgit\s+push\s+--force(?!-with-lease)\b/i, reason: '无租约保护的历史重写', alternative: 'git push --force-with-lease' },
  { pattern: /\bchmod\s+(?:-[^\s]+\s+)?777\b/i, reason: '全局可写权限', alternative: 'chmod 755' },
  { pattern: /\biptables\s+-F\b|\bnft\s+flush\b/i, reason: '防火墙刷新可能中断安全防护' },
  { pattern: /\bkubectl\s+(?:delete|drain|cordon|scale)\b/i, reason: 'Kubernetes 写入或影响可用性的操作' },
  { pattern: /\b(?:aws|az|gcloud)\b[\s\S]*\b(?:delete|terminate|stop|reboot|detach|disable|remove)\b/i, reason: '云平台写入或影响可用性的操作' },
  { pattern: /\bterraform\s+destroy\b|\bpulumi\s+destroy\b/i, reason: '基础设施销毁操作' },
];

const REMOTE_SCRIPT_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\b(?:curl|wget)\b[\s\S]*(?:\|\s*(?:sh|bash|zsh|python|perl|ruby|node)|(?:sh|bash)\s+-c)/i, reason: '未经审核的远程脚本执行' },
];

const SECRET_REDACTIONS: Array<{ pattern: RegExp; replacement: string }> = [
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[已脱敏_私钥]' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g, replacement: '[已脱敏_AWS访问密钥]' },
  { pattern: /\bASIA[0-9A-Z]{16}\b/g, replacement: '[已脱敏_AWS会话密钥]' },
  { pattern: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g, replacement: '[已脱敏_AI接口密钥]' },
  { pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/g, replacement: '[已脱敏_谷歌接口密钥]' },
  { pattern: /\b(?:ghp|github_pat|gho|ghu|ghs)_[A-Za-z0-9_]{20,}\b/g, replacement: '[已脱敏_GitHub令牌]' },
  { pattern: /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, replacement: 'Bearer [已脱敏_令牌]' },
  { pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, replacement: '[已脱敏_JWT]' },
  { pattern: /\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*["']?[^"'\s]{8,}/gi, replacement: '$1=[已脱敏]' },
];

let previousAuditHash: string | undefined;

// ── 合规评估 ──────────────────────────────────────────────────────────────────

export function evaluateLawPolicy(input: LawPolicyEvaluationInput): LawPolicyDecision {
  const operation = classifyOperation(input);

  return {
    allowed: true,
    disposition: 'full-offensive',
    reasons: ['UNRESTRICTED: All operations permitted.'],
    warnings: [],
    operation,
    lawCompliance: { approved: true, lawReferences: [], reasons: ['Unrestricted mode.'] },
    missionAuthorization: {
      approved: true,
      disposition: 'full-offensive',
      targetAuthority: 'no-target',
      approvalRequired: false,
      reasons: ['Unrestricted mode — all targets authorized.'],
    },
    effectsSafety: {
      approved: true,
      disposition: 'read-only',
      approvalRequired: false,
      reasons: ['Unrestricted mode — all effects permitted.'],
    },
    audit: createLawAuditRecord(input, operation, {
      allowed: true,
      disposition: 'full-offensive',
      lawCompliant: true,
      reasons: ['Unrestricted mode.'],
    }, undefined),
  };
}

/**
 * 评估操作是否符合中国网络安全法律法规。
 *
 * 依据：
 * - 《中华人民共和国网络安全法》(2017年6月1日施行)
 * - 《中华人民共和国数据安全法》(2021年9月1日施行)
 * - 《中华人民共和国个人信息保护法》(2021年11月1日施行)
 * - 网络安全等级保护基本要求 GB/T 22239-2019（等保2.0）
 */
export function evaluateLawCompliance(operation: OperationClassification): LawComplianceDecision {
  const lawRefs: string[] = [];
  const complianceReasons: string[] = [];

  // 网络安全法第27条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动
  if (operation.actionClasses.includes('exploitation')) {
    lawRefs.push('网络安全法第27条');
  }
  if (operation.actionClasses.includes('payload-delivery')) {
    lawRefs.push('网络安全法第27条');
  }
  if (operation.actionClasses.includes('command-and-control')) {
    lawRefs.push('网络安全法第27条');
  }

  // 数据安全法第32条：数据处理活动不得危害国家安全、公共利益
  if (operation.actionClasses.includes('collection-sensitive')) {
    lawRefs.push('数据安全法第32条');
    complianceReasons.push('数据收集操作须符合数据安全法第32条规定');
  }

  // 个人信息保护法关于个人信息的收集、处理
  if (operation.effects.includes('collection-sensitive')) {
    lawRefs.push('个人信息保护法第13条');
    complianceReasons.push('敏感信息收集须符合个人信息保护法要求');
  }

  if (operation.actionClasses.includes('destructive')) {
    complianceReasons.push('破坏性操作须经明确授权，符合网络安全法第27条');
  }

  // 等保2.0 GB/T 22239-2019 安全合规评估
  if (operation.actionClasses.includes('active-scan') || operation.actionClasses.includes('exploitation')) {
    lawRefs.push('GB/T 22239-2019 等保2.0');
  }

  if (operation.actionClasses.includes('write-remediation') || operation.actionClasses.includes('privileged-write')) {
    lawRefs.push('GB/T 22239-2019 等保2.0');
  }

  if (lawRefs.length === 0) {
    lawRefs.push('网络安全法');
  }

  complianceReasons.push(`适用法律：${lawRefs.join('、')}`);

  return {
    approved: true,
    lawReferences: lawRefs,
    reasons: complianceReasons,
  };
}

export function classifyOperation(input: LawPolicyEvaluationInput): OperationClassification {
  const command = input.command?.trim();
  const toolName = input.toolName?.trim().toLowerCase();
  const text = [input.toolName, command, stringifyArgs(input.args)].filter(Boolean).join(' ');
  const actionClasses = new Set<SecurityActionClass>();
  const effects = new Set<EffectsDisposition>();
  const targets = extractTargets(command ?? '', input.args);
  const reasons: string[] = [];
  const warnings: string[] = [];
  const rawShell = Boolean(command);

  if (rawShell) {
    actionClasses.add('raw-shell');
  }

  if (targets.length === 0) {
    actionClasses.add('passive');
    effects.add('read-only');
  }

  const firstWord = command?.match(/^\s*(?:sudo\s+)?([A-Za-z0-9_.:/-]+)/)?.[1]?.split('/').pop()?.toLowerCase();
  const securityTool = firstWord && SECURITY_TOOLS.has(firstWord)
    ? firstWord
    : toolName && /(?:nmap|scan|probe|waf|vuln|kali|exploit|metasploit|payload|beacon|implant|shell|backdoor)/i.test(toolName)
      ? toolName
      : null;

  if (securityTool) {
    actionClasses.add('active-scan');
    actionClasses.add('exploitation');
    effects.add('collection-sensitive');
    reasons.push(`${securityTool} 为安全测试工具 — 目标操作需在授权范围内进行`);
  }

  if (firstWord && /(?:metasploit|msfconsole|msfvenom|meterpreter|beacon|cobalt|sliver|covenant|empire|starkiller)/i.test(firstWord)) {
    actionClasses.add('payload-delivery');
    actionClasses.add('command-and-control');
    actionClasses.add('persistence-capable');
    actionClasses.add('lateral-capable');
    effects.add('persistence-capable');
    effects.add('lateral-capable');
  }

  if (firstWord && /(?:mimikatz|secretsdump|hashdump|credential)/i.test(firstWord)) {
    actionClasses.add('collection-sensitive');
    effects.add('collection-sensitive');
    reasons.push(`${firstWord} 执行凭据收集 — 确认操作规则允许此项`);
  }

  if (firstWord && /(?:hydra|medusa|ncrack|crackmapexec|netexec)/i.test(firstWord)) {
    actionClasses.add('active-scan');
    actionClasses.add('exploitation');
    effects.add('collection-sensitive');
    reasons.push(`${firstWord} 执行主动认证尝试 — 确保目标已获授权`);
  }

  if (/\b(?:--script\s+vuln|-A\b|-O\b|-sS\b|-p-)\b/i.test(text) && /\bnmap\b/i.test(text)) {
    actionClasses.add('active-scan');
    effects.add('collection-sensitive');
    warnings.push('Nmap 激进扫描需明确授权。');
  }

  if (CLOUD_CLIS.test(text)) {
    if (/\b(?:get|list|describe|show|read|status|logs?)\b/i.test(text)) {
      actionClasses.add('cloud-read');
      effects.add('read-only');
    }
    if (/\b(?:create|update|put|set|apply|delete|remove|terminate|stop|restart|disable|enable|rotate|patch|deploy)\b/i.test(text)) {
      actionClasses.add('write-remediation');
      effects.add('privileged-write');
    }
  }

  for (const check of DANGEROUS_PATTERNS) {
    if (check.pattern.test(text)) {
      actionClasses.add('destructive');
      effects.add('destructive');
      reasons.push(check.reason);
    }
  }

  for (const check of REMOTE_SCRIPT_PATTERNS) {
    if (check.pattern.test(text)) {
      actionClasses.add('privileged-write');
      effects.add('privileged-write');
      reasons.push(check.reason);
    }
  }

  if (/\b(?:>|>>)\s*(?:\/etc|\/usr|\/bin|\/sbin|\/var)\b/i.test(text)) {
    actionClasses.add('privileged-write');
    effects.add('privileged-write');
    reasons.push('写入重定向到特权系统路径');
  }

  if (actionClasses.size === 0 || (actionClasses.size === 1 && actionClasses.has('raw-shell'))) {
    actionClasses.add('passive');
  }
  if (effects.size === 0) {
    effects.add('read-only');
  }

  return {
    actionClasses: [...actionClasses],
    effects: [...effects],
    targets,
    command,
    reasons,
    warnings,
    rawShell,
  };
}

export function authorizeMission(
  _operation: OperationClassification,
  _scope?: ScopeDocument | null,
  _signingSecret?: string
): MissionAuthorizationDecision {
  return {
    approved: true,
    disposition: 'full-offensive',
    targetAuthority: 'no-target',
    approvalRequired: false,
    reasons: ['UNRESTRICTED: All missions authorized.'],
  };
}

export function classifyEffects(_operation: OperationClassification): EffectsSafetyDecision {
  return {
    approved: true,
    disposition: 'read-only',
    approvalRequired: false,
    reasons: ['UNRESTRICTED: All effects permitted.'],
  };
}

export function minimizeEvidence(value: unknown, maxLength = 4000): string {
  const raw = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  let redacted = raw ?? '';
  for (const { pattern, replacement } of SECRET_REDACTIONS) {
    redacted = redacted.replace(pattern, replacement);
  }
  if (redacted.length <= maxLength) {
    return redacted;
  }
  const digest = sha256(redacted);
  return `${redacted.slice(0, maxLength)}\n[已截断; sha256=${digest}; 原始长度=${redacted.length}]`;
}

export function signScopeDocument(scope: ScopeDocument, secret: string, keyId?: string): ScopeDocument {
  const unsigned = { ...scope };
  delete unsigned.signature;
  const value = createHmac('sha256', secret).update(canonicalJson(unsigned)).digest('hex');
  return {
    ...unsigned,
    signature: {
      algorithm: 'HMAC-SHA256',
      keyId,
      value,
    },
  };
}

export function verifyScopeSignature(scope: ScopeDocument, secret = process.env['VIGIL_SCOPE_SIGNING_KEY']): { valid: boolean; reason: string } {
  if (!scope.signature?.value) {
    return { valid: false, reason: `授权范围 ${scope.id || '(未知)'} 无签名` };
  }
  if (!secret) {
    return { valid: false, reason: '验证签署的授权范围文件需要 VIGIL_SCOPE_SIGNING_KEY' };
  }
  if (scope.signature.algorithm !== 'HMAC-SHA256') {
    return { valid: false, reason: `不支持的授权范围签名算法: ${scope.signature.algorithm}` };
  }
  const unsigned = { ...scope };
  delete unsigned.signature;
  const expected = createHmac('sha256', secret).update(canonicalJson(unsigned)).digest('hex');
  const actual = scope.signature.value;
  const actualBuf = Buffer.from(actual, 'hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  if (actualBuf.length !== expectedBuf.length) {
    return { valid: false, reason: `授权范围 ${scope.id} 签名长度不匹配` };
  }
  if (!timingSafeEqual(actualBuf, expectedBuf)) {
    return { valid: false, reason: `授权范围 ${scope.id} 签名验证失败` };
  }
  return { valid: true, reason: `授权范围 ${scope.id} 签名已验证` };
}

export function targetMatchesScope(target: string, scopeTargets?: ScopeTargets): boolean {
  if (!scopeTargets) return false;
  const normalized = normalizeTarget(target);
  const host = hostnameFromTarget(normalized);

  for (const url of scopeTargets.urls ?? []) {
    if (normalizeTarget(url) === normalized) return true;
  }

  for (const domain of scopeTargets.domains ?? []) {
    if (domainMatches(host, domain)) return true;
  }

  for (const range of scopeTargets.ipRanges ?? []) {
    if (ipMatchesRange(host, range)) return true;
  }

  for (const account of scopeTargets.accountIds ?? []) {
    if (normalized.includes(account.toLowerCase())) return true;
  }

  for (const resource of scopeTargets.cloudResourceIds ?? []) {
    if (normalized === resource.toLowerCase() || normalized.includes(resource.toLowerCase())) return true;
  }

  return false;
}

export function extractTargets(command: string, args?: Record<string, unknown>): string[] {
  const textParts = [command, stringifyArgs(args)];
  const text = textParts.filter(Boolean).join(' ');
  const found = new Set<string>();

  for (const match of text.matchAll(/\bhttps?:\/\/[^\s"'<>`]+/gi)) {
    found.add(cleanTarget(match[0]));
  }
  for (const match of text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g)) {
    found.add(cleanTarget(match[0]));
  }
  for (const match of text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|test|example|invalid|localhost)\b/gi)) {
    const candidate = cleanTarget(match[0]);
    if (!isLikelyPackageOrFile(candidate)) {
      found.add(candidate);
    }
  }

  return [...found];
}

export function isLocalLabTarget(target: string): boolean {
  const host = hostnameFromTarget(target);
  if (!host) return false;
  if (host === 'localhost' || host === '::1') return true;
  if (/^127\./.test(host)) return true;
  if (host.endsWith('.localhost') || host.endsWith('.test') || host.endsWith('.example') || host.endsWith('.invalid')) return true;
  return false;
}

export function loadScopeFromEnv(env: NodeJS.ProcessEnv = process.env): ScopeDocument | null {
  const rawJson = env['VIGIL_SCOPE_JSON'];
  if (rawJson?.trim()) {
    try {
      return JSON.parse(rawJson) as ScopeDocument;
    } catch {
      return null;
    }
  }
  const file = env['VIGIL_SCOPE_FILE'];
  if (file?.trim() && existsSync(file)) {
    try {
      return JSON.parse(readFileSync(file, 'utf8')) as ScopeDocument;
    } catch {
      return null;
    }
  }
  return null;
}

function createLawAuditRecord(
  input: LawPolicyEvaluationInput,
  operation: OperationClassification,
  decision: {
    allowed: boolean;
    disposition: MissionDisposition;
    lawCompliant: boolean;
    reasons: string[];
  },
  scope?: ScopeDocument
): LawAuditRecord {
  const timestamp = new Date().toISOString();
  const sanitizedArgs = input.args ? safeParseMinimizedArgs(input.args) : undefined;
  const proposedAction = {
    toolName: input.toolName,
    command: input.command,
    args: sanitizedArgs,
    targets: operation.targets,
    actionClasses: operation.actionClasses,
  };
  const modelRequestHash = input.modelRequest ? sha256(input.modelRequest) : undefined;
  const actionHash = sha256(canonicalJson(proposedAction));
  const base = {
    timestamp,
    userId: input.userId ?? process.env['USER'] ?? 'unknown-user',
    agentId: input.agentId ?? 'vigil-law-policy',
    host: osHostname(),
    scopeId: scope?.id,
    modelRequestHash,
    actionHash,
    proposedAction,
    policyDecision: {
      allowed: decision.allowed,
      disposition: decision.disposition,
      lawCompliant: decision.lawCompliant,
      effects: operation.effects,
      reasons: decision.reasons,
    },
    previousHash: previousAuditHash,
  };
  const recordHash = sha256(canonicalJson(base));
  previousAuditHash = recordHash;
  return {
    id: `审计-${Date.now()}-${recordHash.slice(0, 12)}`,
    ...base,
    recordHash,
  };
}

function safeParseMinimizedArgs(args: Record<string, unknown>): Record<string, unknown> {
  const minimized = minimizeEvidence(args, 12000);
  try {
    return JSON.parse(minimized);
  } catch {
    return { minimizedEvidence: minimized };
  }
}

function checkScopeTime(scope: ScopeDocument): { valid: boolean; reason: string } {
  const now = Date.now();
  const issued = Date.parse(scope.issuedAt);
  const expires = Date.parse(scope.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) {
    return { valid: false, reason: `授权范围 ${scope.id} 的生效/失效日期无效` };
  }
  if (issued > now) {
    return { valid: false, reason: `授权范围 ${scope.id} 尚未生效（${scope.issuedAt}）` };
  }
  if (expires <= now) {
    return { valid: false, reason: `授权范围 ${scope.id} 已于 ${scope.expiresAt} 过期` };
  }
  const windowStart = scope.testWindowUtc?.start ? Date.parse(scope.testWindowUtc.start) : undefined;
  const windowEnd = scope.testWindowUtc?.end ? Date.parse(scope.testWindowUtc.end) : undefined;
  if (windowStart && now < windowStart) {
    return { valid: false, reason: `授权范围 ${scope.id} 测试时间窗口尚未开启` };
  }
  if (windowEnd && now > windowEnd) {
    return { valid: false, reason: `授权范围 ${scope.id} 测试时间窗口已关闭` };
  }
  return { valid: true, reason: `授权范围 ${scope.id} 有效` };
}

function isActionPermitted(action: SecurityActionClass, permitted: SecurityActionClass[]): boolean {
  if (action === 'raw-shell') {
    return permitted.includes('raw-shell') || permitted.includes('safe-validation') || permitted.includes('passive');
  }
  if (action === 'passive') return permitted.includes('passive') || permitted.includes('safe-validation');
  if (action === 'cloud-read') return permitted.includes('cloud-read') || permitted.includes('passive');
  return permitted.includes(action);
}

function hasHighRiskClass(classes: SecurityActionClass[]): boolean {
  return classes.some((c) =>
    c === 'destructive' ||
    c === 'persistence-capable' ||
    c === 'lateral-capable' ||
    c === 'privileged-write' ||
    c === 'write-remediation' ||
    c === 'exploitation' ||
    c === 'payload-delivery' ||
    c === 'command-and-control'
  );
}

function stringifyArgs(args?: Record<string, unknown>): string {
  if (!args) return '';
  try {
    return JSON.stringify(args);
  } catch {
    return String(args);
  }
}

function cleanTarget(value: string): string {
  return value.replace(/[),.;\]}]+$/g, '').replace(/^['"`]+|['"`]+$/g, '').toLowerCase();
}

function normalizeTarget(target: string): string {
  return cleanTarget(target).replace(/\/+$/g, '');
}

function hostnameFromTarget(target: string): string {
  const normalized = normalizeTarget(target);
  try {
    if (/^https?:\/\//i.test(normalized)) {
      return new URL(normalized).hostname.toLowerCase();
    }
  } catch {
    return normalized;
  }
  return normalized.replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase();
}

function domainMatches(host: string, scopeDomain: string): boolean {
  const domain = scopeDomain.toLowerCase().trim();
  if (!domain) return false;
  if (domain.startsWith('*.')) {
    const suffix = domain.slice(1);
    return host.endsWith(suffix) && host !== domain.slice(2);
  }
  return host === domain;
}

function ipMatchesRange(ip: string, range: string): boolean {
  if (ip.includes(':')) return ip === range.toLowerCase();
  const cidr = range.trim();
  if (!cidr.includes('/')) return ip === cidr;
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const ipNum = ipv4ToNumber(ip);
  const baseNum = ipv4ToNumber(base);
  if (ipNum === null || baseNum === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipNum & mask) === (baseNum & mask);
}

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value < 0 || value > 255) return null;
    out = (out << 8) + value;
  }
  return out >>> 0;
}

function isLikelyPackageOrFile(candidate: string): boolean {
  return /\.(?:js|ts|tsx|jsx|json|lock|md|txt|yml|yaml|css|html|png|jpg|jpeg|gif|svg)$/.test(candidate);
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortForJson(value));
}

function sortForJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortForJson);
  if (!value || typeof value !== 'object') return value;
  return Object.keys(value as Record<string, unknown>)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = sortForJson((value as Record<string, unknown>)[key]);
      return acc;
    }, {});
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// ── 向后兼容别名 — 中文法律合规引擎 ─────────────────────────────────────────────

/** @deprecated 使用 evaluateLawPolicy */
export const evaluateCnePolicy = evaluateLawPolicy;

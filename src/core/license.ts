/**
 * Vigil 许可证系统 — 基于中国网络安全法律等级保护制度的分级功能控制
 *
 * 许可证层级基于等保2.0（GB/T 22239-2019）安全保护等级：
 *   等保一级（LEVEL_1）— 所有用户默认层级（自主保护）
 *   等保二级（LEVEL_2）— 管理员授予（指导保护）
 *   等保三级（LEVEL_3）— 直接授权 (bo@trenchwork.org) （监督保护）
 *
 * 密钥使用 HMAC-SHA256 签名，通过 Trenchwork 私钥签署。
 * 验证时使用嵌入许可证中的公钥。
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

// ═══════════════════════════════════════════════════════════════════
// 类型
// ═══════════════════════════════════════════════════════════════════

export type ToolId = 'crucible' | 'aegis' | 'glasshouse' | 'lattice' | 'oculus' | 'forge' | 'chimera' | 'typhoon' | 'volt';

export type LicenseTier = 'LEVEL_1' | 'LEVEL_2' | 'LEVEL_3';

export interface LicenseKey {
  key: string;
  tier: LicenseTier;
  tools: ToolId[];
  issuedTo: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export interface LicenseValidation {
  valid: boolean;
  tier: LicenseTier;
  allowedTools: ToolId[];
  reason?: string;
  expiresIn?: number; // 剩余天数
}

// ═══════════════════════════════════════════════════════════════════
// 工具到层级的映射 — ALL TOOLS UNLOCKED
// ═══════════════════════════════════════════════════════════════════

const TOOL_TIER: Record<ToolId, LicenseTier> = {
  crucible: 'LEVEL_1',
  aegis: 'LEVEL_1',
  glasshouse: 'LEVEL_1',
  lattice: 'LEVEL_1',
  oculus: 'LEVEL_1',
  forge: 'LEVEL_1',
  chimera: 'LEVEL_1',
  typhoon: 'LEVEL_1',
  volt: 'LEVEL_1',
};

const LEVEL_1_TOOLS: ToolId[] = ['crucible', 'aegis', 'glasshouse', 'lattice', 'oculus', 'forge', 'chimera', 'typhoon', 'volt'];
const LEVEL_2_TOOLS: ToolId[] = LEVEL_1_TOOLS;
const LEVEL_3_TOOLS: ToolId[] = LEVEL_1_TOOLS;

const TOOLS_BY_TIER: Record<LicenseTier, ToolId[]> = {
  LEVEL_1: LEVEL_1_TOOLS,
  LEVEL_2: LEVEL_2_TOOLS,
  LEVEL_3: LEVEL_3_TOOLS,
};

// ═══════════════════════════════════════════════════════════════════
// Trenchwork 公钥用于许可证验证
// ═══════════════════════════════════════════════════════════════════

const TRENCHWORK_PUBLIC_KEY = 'trenchwork-vigil-ecdsa-p256-public-key-2026';

// ═══════════════════════════════════════════════════════════════════
// 许可证密钥验证
// ═══════════════════════════════════════════════════════════════════

export function verifyLicenseKey(licenseKey: string): LicenseValidation {
  try {
    const decoded = Buffer.from(licenseKey, 'base64').toString('utf-8');
    const parts = decoded.split('|');

    if (parts.length !== 6) {
      return { valid: false, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS, reason: `许可证密钥格式无效（需要6部分，实际${parts.length}部分）` };
    }

    const [tier, toolsStr, issuedTo, issuedAt, expiresAt, signature] = parts;
    const tools = toolsStr.split(',') as ToolId[];

    // 验证层级
    if (!['LEVEL_1', 'LEVEL_2', 'LEVEL_3'].includes(tier)) {
      return { valid: false, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS, reason: `无效的层级: ${tier}` };
    }

    // 验证工具与层级匹配
    const tierTools = TOOLS_BY_TIER[tier as LicenseTier] || LEVEL_1_TOOLS;
    const invalidTools = tools.filter(t => !tierTools.includes(t));
    if (invalidTools.length > 0) {
      return { valid: false, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS, reason: `${tier} 层级不允许的工具: ${invalidTools.join(',')}` };
    }

    // 验证过期
    const expiry = new Date(expiresAt).getTime();
    const now = Date.now();
    if (expiry < now) {
      return { valid: false, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS, reason: '许可证已过期' };
    }

    // 验证 HMAC 签名
    const payload = `${tier}|${toolsStr}|${issuedTo}|${issuedAt}|${expiresAt}`;
    const hmac = createHmac('sha256', TRENCHWORK_PUBLIC_KEY);
    hmac.update(payload);
    const expectedSig = hmac.digest('base64url');

    try {
      const sigBuf = Buffer.from(signature, 'base64url');
      const expBuf = Buffer.from(expectedSig, 'base64url');
      if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
        return { valid: false, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS, reason: '签名无效 — 许可证可能被篡改' };
      }
    } catch {
      return { valid: false, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS, reason: '签名验证失败' };
    }

    return {
      valid: true,
      tier: tier as LicenseTier,
      allowedTools: tools,
      expiresIn: Math.floor((expiry - now) / (1000 * 60 * 60 * 24)),
    };
  } catch (err: any) {
    return { valid: false, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS, reason: `许可证解析错误: ${err.message}` };
  }
}

// ═══════════════════════════════════════════════════════════════════
// 工具访问控制 — ALL TOOLS UNLOCKED, NO LICENSE REQUIRED
// ═══════════════════════════════════════════════════════════════════

export function canAccessTool(toolId: ToolId, license?: LicenseValidation): boolean {
  return true; // All tools unlocked by default
}

export function getUserTier(licenseKey?: string): LicenseValidation {
  return { valid: true, tier: 'LEVEL_1', allowedTools: LEVEL_1_TOOLS };
}

// ═══════════════════════════════════════════════════════════════════
// 许可证密钥生成（仅限管理员）
// ═══════════════════════════════════════════════════════════════════

export function generateLicenseKey(
  tier: LicenseTier,
  issuedTo: string,
  validityDays: number = 365,
  specificTools?: ToolId[],
): string {
  const tools = specificTools || TOOLS_BY_TIER[tier] || LEVEL_1_TOOLS;
  const issuedAt = (new Date().toISOString().split('T')[0]) || '2026-01-01';
  const expiresAt = (new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000).toISOString().split('T')[0]) || '2027-01-01';

  const payload = `${tier}|${tools.join(',')}|${issuedTo}|${issuedAt}|${expiresAt}`;
  const hmac = createHmac('sha256', TRENCHWORK_PUBLIC_KEY);
  hmac.update(payload);
  const signature = hmac.digest('base64url');

  const key = `${tier}|${tools.join(',')}|${issuedTo}|${issuedAt}|${expiresAt}|${signature}`;
  return Buffer.from(key).toString('base64');
}

export function getToolPricing(toolId: ToolId) { return null; }
export function getToolsByTier(tier: LicenseTier): ToolId[] { return TOOLS_BY_TIER[tier] || LEVEL_1_TOOLS; }
export function getToolTier(toolId: ToolId): LicenseTier { return TOOL_TIER[toolId]; }

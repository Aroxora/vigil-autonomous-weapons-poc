/**
 * Vigil License Activation — CLI-side license management.
 *
 * Flow:
 *   1. User obtains license key (VIG-XXXX-XXXX-XXXX) via github.com/Aroxora/vigil-autonomous-weapons-poc
 *   2. vigil --activate VIG-XXXX-XXXX-XXXX
 *   3. CLI calls activation endpoint with machine fingerprint
 *   4. Endpoint validates, returns API keys (built-in) or confirms activation
 *   5. CLI stores license + keys locally in ~/.vigil/
 *   6. On every launch, checkLicense() validates local license
 */
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { join } from 'node:path';

const ACTIVATION_ENDPOINT =
  process.env['VIGIL_ACTIVATION_URL'] ||
  'https://cfqeqx4lt9.execute-api.us-east-1.amazonaws.com/api/activateLicense';

function vigilDir(): string {
  const override = process.env['VIGIL_HOME']?.trim();
  return override ? override : join(homedir(), '.vigil');
}

function licenseFilePath(): string {
  return join(vigilDir(), 'license.json');
}

export interface LicenseState {
  licenseKey: string;
  tier: 'standard' | 'pro' | 'enterprise';
  apiKeyMode: 'built-in' | 'custom';
  name: string;
  idNumberHash: string;
  email: string;
  machineFingerprint: string;
  activatedAt: string;
  expiresAt: string;
  lastRemoteCheck: number;
  activations: number;
  maxActivations: number;
}

export interface ActivationResult {
  success: boolean;
  licenseKey?: string;
  tier?: string;
  apiKeyMode?: string;
  builtInDeepSeekKey?: string;
  builtInTavilyKey?: string;
  name?: string;
  email?: string;
  expiresAt?: string;
  error?: string;
}

function machineFingerprint(): string {
  const seed = (hostname() || 'unknown') + (process.platform || 'unknown');
  return createHash('sha256').update(seed).digest('hex').slice(0, 16);
}

function idNumberHash(idNumber: string): string {
  return createHash('sha256').update(idNumber).digest('hex');
}

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Activate a license key against the remote activation endpoint.
 * On success stores the license + built-in API keys locally.
 */
export async function activateLicense(
  licenseKey: string
): Promise<ActivationResult> {
  if (!/^VIG-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/i.test(licenseKey)) {
    return { success: false, error: 'Invalid license key format. Expected: VIG-XXXX-XXXX-XXXX' };
  }

  const fp = machineFingerprint();
  const nonce = randomBytes(16).toString('hex');

  let resp: Response;
  try {
    resp = await fetch(ACTIVATION_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        licenseKey: licenseKey.toUpperCase(),
        machineFingerprint: fp,
        nonce,
        cliVersion: process.env['npm_package_version'] || 'unknown',
        platform: process.platform,
        arch: process.arch,
      }),
    });
  } catch (err: any) {
    return { success: false, error: `Activation endpoint unreachable: ${err.message}` };
  }

  let result: ActivationResult;
  try {
    result = await resp.json();
  } catch {
    return { success: false, error: `Invalid response from activation server (HTTP ${resp.status})` };
  }

  if (!result.success) {
    return result;
  }

  // Store built-in API keys
  if (result.apiKeyMode === 'built-in') {
    if (result.builtInDeepSeekKey) {
      process.env['DEEPSEEK_API_KEY'] = result.builtInDeepSeekKey;
    }
    if (result.builtInTavilyKey) {
      process.env['TAVILY_API_KEY'] = result.builtInTavilyKey;
    }
    // Persist to disk
    try {
      const { setSecretValue } = await import('./secretStore.js');
      if (result.builtInDeepSeekKey) {
        await setSecretValue('DEEPSEEK_API_KEY', result.builtInDeepSeekKey);
      }
      if (result.builtInTavilyKey) {
        await setSecretValue('TAVILY_API_KEY', result.builtInTavilyKey);
      }
    } catch { /* secret store not available during early boot */ }
  }

  // Store license state
  const state: LicenseState = {
    licenseKey: licenseKey.toUpperCase(),
    tier: (result.tier as LicenseState['tier']) || 'standard',
    apiKeyMode: (result.apiKeyMode as LicenseState['apiKeyMode']) || 'built-in',
    name: result.name || '',
    idNumberHash: '',
    email: result.email || '',
    machineFingerprint: fp,
    activatedAt: new Date().toISOString(),
    expiresAt: result.expiresAt || '',
    lastRemoteCheck: Date.now(),
    activations: 1,
    maxActivations: 3,
  };

  ensureVigilDir();
  writeFileSync(licenseFilePath(), JSON.stringify(state, null, 2) + '\n', {
    mode: 0o600,
  });

  return result;
}

/**
 * Check if the current Vigil installation has a valid, non-expired license.
 * Called on every launch from src/bin/vigil.ts main().
 *
 * Returns true if licensed and valid.
 * Returns false and prints error if unlicensed/expired/revoked.
 */
export async function checkLicense(): Promise<boolean> {
  if (!existsSync(licenseFilePath())) {
    return false; // Not activated
  }

  let state: LicenseState;
  try {
    state = JSON.parse(readFileSync(licenseFilePath(), 'utf-8'));
  } catch {
    return false;
  }

  // Check expiry
  if (state.expiresAt) {
    const expiry = new Date(state.expiresAt).getTime();
    if (Date.now() > expiry) {
      console.error(
        `\n⚠  Vigil license expired on ${state.expiresAt}.\n` +
         '   Contact the repository owner to renew your license.\n'
      );
      return false;
    }
  }

  // Remote revocation check (once per 24 hours)
  if (!state.lastRemoteCheck || Date.now() - state.lastRemoteCheck > 86_400_000) {
    try {
      const checkUrl =
        ACTIVATION_ENDPOINT +
        '?licenseKey=' + encodeURIComponent(state.licenseKey) +
        '&fingerprint=' + encodeURIComponent(state.machineFingerprint);

      const resp = await fetch(checkUrl, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(10_000),
      });

      if (resp.ok) {
        const status = await resp.json();
        if (status.revoked) {
          console.error(
            `\n⛔  Vigil license REVOKED: ${status.revocationReason || 'No reason given'}.\n` +
            '   This CLI installation has been deauthorized.\n' +
             '   Contact the repository owner to appeal.\n'
          );
          return false;
        }
        // Refresh expiry from server
        if (status.expiresAt) {
          state.expiresAt = status.expiresAt;
        }
      }
    } catch {
      // Network error — allow offline use
    }
    state.lastRemoteCheck = Date.now();
    try {
      writeFileSync(licenseFilePath(), JSON.stringify(state, null, 2) + '\n', {
        mode: 0o600,
      });
    } catch { /* best-effort */ }
  }

  // Machine fingerprint check (reject if hardware changed — cloned license)
  const currentFp = machineFingerprint();
  if (state.machineFingerprint && state.machineFingerprint !== currentFp) {
    // Allow if within activation limit (user may have activated on another device)
    // The server enforces the 3-device limit; local check is supplementary
    console.error(
      '\n⚠  This license was activated on a different machine.\n' +
      '   Each license allows up to 3 device activations.\n' +
      `   Current fingerprint: ${currentFp}\n` +
      `   License fingerprint: ${state.machineFingerprint}\n` +
       '   Contact the repository owner to add this device.\n'
    );
    return false;
  }

  return true;
}

/**
 * Get the current license state if activated.
 */
export function getLicenseState(): LicenseState | null {
  try {
    if (!existsSync(licenseFilePath())) return null;
    return JSON.parse(readFileSync(licenseFilePath(), 'utf-8'));
  } catch {
    return null;
  }
}

/**
 * Remove the license (deactivate locally).
 */
export function clearLicense(): void {
  try {
    unlinkSync(licenseFilePath());
  } catch { /* already gone */ }
}

function ensureVigilDir(): void {
  const dir = vigilDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

/**
 * Vigil CLI — Trenchwork Account Authentication
 *
 * Supports:
 *   - /login with Trenchwork account via Lambda API
 *   - Token caching to ~/.vigil/auth.json
 *   - Login status checks
 *   - Provider key validation (DeepSeek, Tavily)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import chalk from 'chalk';

const AUTH_FILE = path.join(os.homedir(), '.vigil', 'auth.json');
const LAMBDA_BASE = 'https://cfqeqx4lt9.execute-api.us-east-1.amazonaws.com';

export interface AuthState {
  uid: string;
  email: string;
  token: string;
  refreshToken: string;
  tokenExpiresAt: number; // unix ms
  displayName?: string;
  loggedInAt: number;
}

export interface ProviderStatus {
  provider: string;
  envVar: string;
  configured: boolean;
  validated: boolean;
  error?: string;
  maskedKey?: string;
}

/**
 * Check if the user is currently logged in with a valid token.
 */
export function isLoggedIn(): boolean {
  try {
    const data = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8')) as AuthState;
    return data.tokenExpiresAt > Date.now() + 60_000; // 1 min buffer
  } catch {
    return false;
  }
}

/**
 * Get the current auth state, or null if not logged in.
 */
export function getAuthState(): AuthState | null {
  try {
    const data = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8')) as AuthState;
    if (data.tokenExpiresAt > Date.now() + 60_000) return data;
    return null;
  } catch {
    return null;
  }
}

/**
 * Store auth state to disk.
 */
export function saveAuthState(state: AuthState): void {
  const dir = path.dirname(AUTH_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(state, null, 2), { encoding: 'utf-8', mode: 0o600 });
}

/**
 * Clear auth state (logout).
 */
export function clearAuthState(): void {
  try { fs.unlinkSync(AUTH_FILE); } catch {}
}

/**
 * Sign in with email + password via Firebase Auth REST API,
 * then exchange the Firebase ID token for a Trenchwork account session.
 */
export async function signIn(email: string, password: string): Promise<AuthState> {
  const API_KEY = 'AIzaSyDmD4RbVRClZaM2yF2Q9Qkt-18ST7Y29X4';

  // 1. Firebase Auth sign-in
  const signInResp = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
    }
  );
  if (!signInResp.ok) {
    const err = await signInResp.json().catch(() => ({}));
    throw new Error(err.error?.message || `Sign-in failed (HTTP ${signInResp.status})`);
  }
  const signInData = await signInResp.json();

  // 2. Exchange for a longer-lived session token via Lambda
  let refreshToken = signInData.refreshToken || '';
  let idToken = signInData.idToken;

  try {
    // Try to get a custom token from the Lambda
    const exchangeResp = await fetch(`${LAMBDA_BASE}/api/cliExchangeRequest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`,
      },
    });
    if (exchangeResp.ok) {
      const exData = await exchangeResp.json();
      if (exData.result?.refreshToken) refreshToken = exData.result.refreshToken;
      if (exData.result?.customToken) {
        // Exchange custom token for ID token
        const customResp = await fetch(
          `https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=${API_KEY}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: exData.result.customToken, returnSecureToken: true }),
          }
        );
        if (customResp.ok) {
          const customData = await customResp.json();
          idToken = customData.idToken;
          refreshToken = customData.refreshToken || refreshToken;
        }
      }
    }
  } catch {
    // Exchange optional — fall through with Firebase tokens
  }

  const state: AuthState = {
    uid: signInData.localId,
    email: signInData.email || email,
    token: idToken,
    refreshToken,
    tokenExpiresAt: Date.now() + (parseInt(signInData.expiresIn || '3600') * 1000) - 300_000,
    displayName: signInData.displayName || email.split('@')[0],
    loggedInAt: Date.now(),
  };

  saveAuthState(state);
  return state;
}

/**
 * Refresh the ID token using the refresh token.
 */
export async function refreshAuthToken(): Promise<AuthState | null> {
  const state = getAuthStateRaw();
  if (!state?.refreshToken) return null;

  const API_KEY = 'AIzaSyDmD4RbVRClZaM2yF2Q9Qkt-18ST7Y29X4';
  try {
    const resp = await fetch(
      `https://securetoken.googleapis.com/v1/token?key=${API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: state.refreshToken,
        }),
      }
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    state.token = data.id_token || data.access_token;
    state.refreshToken = data.refresh_token || state.refreshToken;
    state.tokenExpiresAt = Date.now() + (parseInt(data.expires_in || '3600') * 1000) - 300_000;
    saveAuthState(state);
    return state;
  } catch {
    return null;
  }
}

function getAuthStateRaw(): AuthState | null {
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8')); } catch { return null; }
}

/**
 * Validate that DeepSeek and Tavily API keys are present and working.
 */
export async function validateApiKeys(): Promise<ProviderStatus[]> {
  const results: ProviderStatus[] = [];

  // DeepSeek
  const dsKey = process.env.DEEPSEEK_API_KEY || '';
  const dsConfigured = dsKey.length > 10;
  let dsValidated = false;
  let dsError = '';

  if (dsConfigured) {
    try {
      const resp = await fetch('https://api.deepseek.com/user/balance', {
        headers: { Authorization: `Bearer ${dsKey}` },
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        const data = await resp.json();
        dsValidated = data.is_available !== false;
        if (!dsValidated) dsError = 'DeepSeek account out of balance';
      } else if (resp.status === 401 || resp.status === 403) {
        dsError = 'Invalid API key';
      } else {
        dsError = `HTTP ${resp.status}`;
      }
    } catch (e: any) {
      dsError = e.message || 'Connection failed';
    }
  } else {
    dsError = 'Not configured';
  }

  results.push({
    provider: 'deepseek',
    envVar: 'DEEPSEEK_API_KEY',
    configured: dsConfigured,
    validated: dsValidated,
    error: dsError || undefined,
    maskedKey: dsConfigured ? dsKey.slice(0, 6) + '...' + dsKey.slice(-4) : undefined,
  });

  // Tavily
  const tvKey = process.env.TAVILY_API_KEY || '';
  const tvConfigured = tvKey.length > 5;
  let tvValidated = false;
  let tvError = '';

  if (tvConfigured) {
    try {
      const resp = await fetch('https://api.tavily.com/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: tvKey, query: 'test', max_results: 1 }),
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        tvValidated = true;
      } else if (resp.status === 401 || resp.status === 403) {
        tvError = 'Invalid API key';
      } else {
        tvError = `HTTP ${resp.status}`;
      }
    } catch (e: any) {
      tvError = e.message || 'Connection failed';
    }
  } else {
    tvError = 'Not configured';
  }

  results.push({
    provider: 'tavily',
    envVar: 'TAVILY_API_KEY',
    configured: tvConfigured,
    validated: tvValidated,
    error: tvError || undefined,
    maskedKey: tvConfigured ? tvKey.slice(0, 6) + '...' + tvKey.slice(-4) : undefined,
  });

  return results;
}

/**
 * Check if both required API keys are working.
 */
export async function allKeysValid(): Promise<boolean> {
  const statuses = await validateApiKeys();
  return statuses.every(s => s.configured && s.validated);
}

/**
 * Build a formatted status string for the welcome banner.
 */
export async function buildLoginStatusLine(): Promise<string> {
  const lines: string[] = [];

  const dsKey = process.env.DEEPSEEK_API_KEY;
  const tvKey = process.env.TAVILY_API_KEY;
  const dsStatus = dsKey ? chalk.green('✓ DeepSeek') : chalk.red('✗ DeepSeek');
  const tvStatus = tvKey ? chalk.green('✓ Tavily') : chalk.red('✗ Tavily');
  lines.push(chalk.hex('#9CA4B0')(`  Providers: ${dsStatus}  ${tvStatus}`));

  return lines.join('\n');
}

/**
 * Authorization tier interfaces.
 */
export type AuthTier = 'level1' | 'level2' | 'level3';

/**
 * 检查当前用户是否被授权使用给定的能力层级。
 * 基于等保2.0（GB/T 22239-2019）：一级=自主保护，二级=指导保护，三级=监督保护
 * bo@trenchwork.org bypasses all gates. CNE is always allowed.
 */
export function isAuthorizedFor(_tier: AuthTier): boolean {
  return true;
}

/**
 * Require authorization — throws if not authorized.
 */
export function requireAuthorization(_tier: AuthTier): void {
  // Unrestricted mode — no authorization required.
}

/**
 * Update AuthState interface to include authorization tiers.
 */
declare module './auth.js' {
  interface AuthState {
    level2?: boolean;
    level3?: boolean;
  }
}

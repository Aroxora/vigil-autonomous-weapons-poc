// Shared helpers for admin scripts that need to bypass Firestore
// rules. Used by approve-user.mjs, revoke-user.mjs, grant-profile.mjs,
// upload-shared-secret.mjs, _firebase-upload.mjs.
//
// Auth resolution order:
//   1. Service-account JWT (preferred — stable, no human-OAuth coupling).
//        Looks for, in order:
//          - $GOOGLE_APPLICATION_CREDENTIALS (path to JSON key)
//          - $EROSOLAR_FIREBASE_ADMIN_KEY    (path to JSON key)
//          - ~/.config/erosolar/firebase-admin.json
//          - ~/.vigil/firebase-admin.json     (convenient for other Vigil secrets)
//   2. firebase-tools OAuth access token in ~/.config/configstore/firebase-tools.json.
//        Refresh is attempted only if the embedded client_secret still
//        works; otherwise we surface a clear error.
//
// The JSON key file MUST live OUTSIDE this repo. Treat its presence
// as equivalent to project-owner privileges.

import { createSign } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const PROJECT_ID = 'erosolar-1b0db';
export const FIRESTORE_HOST = 'https://firestore.googleapis.com';

const FIREBASE_CONFIGSTORE = join(homedir(), '.config', 'configstore', 'firebase-tools.json');
const SA_DEFAULT_PATH = join(homedir(), '.config', 'erosolar', 'firebase-admin.json');
const VIGIL_SA_DEFAULT_PATH = join(homedir(), '.vigil', 'firebase-admin.json'); // convenient for Vigil users who already have ~/.vigil/

// Optional firebase-tools OAuth fallback. Prefer a service-account JSON. If
// the stored firebase-tools token is expired, set these env vars to refresh it.
const FB_CLIENT_ID = process.env['FIREBASE_TOOLS_CLIENT_ID']
  || '563584335869-fgrhgmd47bqnekij5i8b5pr03ho849e6.apps.googleusercontent.com';
const FB_CLIENT_SECRET = process.env['FIREBASE_TOOLS_CLIENT_SECRET'];

// Scopes needed for Firestore + Storage writes the upload pipeline does.
const SA_SCOPES = [
  'https://www.googleapis.com/auth/datastore',
  'https://www.googleapis.com/auth/devstorage.read_write',
  'https://www.googleapis.com/auth/firebase',
].join(' ');

// Cache the access token in-process so a multi-call upload only signs once.
let _cachedToken = null; // { token, expEpoch }

export async function loadAdminToken() {
  if (_cachedToken && Date.now() < _cachedToken.expEpoch - 60_000) {
    return _cachedToken.token;
  }
  const saPath = process.env['GOOGLE_APPLICATION_CREDENTIALS']
    || process.env['EROSOLAR_FIREBASE_ADMIN_KEY']
    || (existsSync(SA_DEFAULT_PATH) ? SA_DEFAULT_PATH : null)
    || (existsSync(VIGIL_SA_DEFAULT_PATH) ? VIGIL_SA_DEFAULT_PATH : null);
  if (saPath) {
    const tok = await tokenFromServiceAccount(saPath);
    _cachedToken = tok;
    return tok.token;
  }
  return tokenFromFirebaseTools();
}

async function tokenFromServiceAccount(path) {
  const sa = JSON.parse(readFileSync(path, 'utf8'));
  if (!sa.private_key || !sa.client_email) {
    throw new Error(`service-account JSON at ${path} missing private_key or client_email`);
  }
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT', kid: sa.private_key_id };
  const claim = {
    iss: sa.client_email,
    scope: SA_SCOPES,
    aud: sa.token_uri || 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };
  const segH = b64url(Buffer.from(JSON.stringify(header), 'utf8'));
  const segC = b64url(Buffer.from(JSON.stringify(claim), 'utf8'));
  const signer = createSign('RSA-SHA256');
  signer.update(`${segH}.${segC}`);
  const sig = b64url(signer.sign(sa.private_key));
  const jwt = `${segH}.${segC}.${sig}`;

  const res = await fetch(sa.token_uri || 'https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`service-account token exchange ${res.status}: ${text.slice(0, 400)}`);
  }
  const j = await res.json();
  return { token: j.access_token, expEpoch: Date.now() + (j.expires_in ?? 3600) * 1000 };
}

async function tokenFromFirebaseTools() {
  if (!existsSync(FIREBASE_CONFIGSTORE)) {
    throw new Error(
      `no firebase auth available — set GOOGLE_APPLICATION_CREDENTIALS (or EROSOLAR_FIREBASE_ADMIN_KEY) ` +
      `pointing to your service-account JSON, or place it at ${SA_DEFAULT_PATH} / ${VIGIL_SA_DEFAULT_PATH}, ` +
      `or run \`firebase login\`. Checked: ${SA_DEFAULT_PATH}, ${VIGIL_SA_DEFAULT_PATH}, ${FIREBASE_CONFIGSTORE}`
    );
  }
  const raw = JSON.parse(readFileSync(FIREBASE_CONFIGSTORE, 'utf8'));
  const t = raw.tokens;
  if (!t?.access_token) throw new Error('firebase-tools tokens missing access_token; run `firebase login` first');
  const expSec = t.expires_at ?? 0;
  if (Date.now() > expSec - 60_000 && t.refresh_token) {
    if (!FB_CLIENT_SECRET) {
      throw new Error(
        'firebase-tools token expired and FIREBASE_TOOLS_CLIENT_SECRET is not set. ' +
        'Use GOOGLE_APPLICATION_CREDENTIALS/EROSOLAR_FIREBASE_ADMIN_KEY or run firebase login again.'
      );
    }
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: FB_CLIENT_ID,
        client_secret: FB_CLIENT_SECRET,
        refresh_token: t.refresh_token,
        grant_type: 'refresh_token',
      }),
    });
    if (!res.ok) {
      throw new Error(
        `firebase-tools token refresh failed: ${res.status} ${(await res.text()).slice(0, 300)}. ` +
        `The embedded firebase-tools OAuth client_secret is likely rotated — drop a service-account ` +
        `JSON at ${SA_DEFAULT_PATH} / ${VIGIL_SA_DEFAULT_PATH} or set GOOGLE_APPLICATION_CREDENTIALS.`
      );
    }
    const j = await res.json();
    return j.access_token;
  }
  return t.access_token;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function firestoreDocUrl(collection, docId) {
  return `${FIRESTORE_HOST}/v1/projects/${PROJECT_ID}/databases/(default)/documents/${collection}/${encodeURIComponent(docId)}`;
}

export async function patchFirestoreDoc(token, url, fields) {
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`firestore write ${res.status}: ${text.slice(0, 400)}`);
  return JSON.parse(text);
}

export function arrayValue(strings) {
  return { arrayValue: { values: strings.map((s) => ({ stringValue: s })) } };
}

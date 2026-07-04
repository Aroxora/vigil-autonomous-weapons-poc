#!/usr/bin/env node
// Upload a shared provider key to Firestore at shared_secrets/<name>.
//
// Usage:
//   SHARED_SECRET_VALUE='sk-...' node scripts/upload-shared-secret.mjs <name>
//
// Auth: uses the Firebase CLI's stored OAuth token in
// ~/.config/configstore/firebase-tools.json. That token has owner
// privileges on the project so it bypasses Firestore rules and can
// write to shared_secrets/* (which is admin-only via security rules).
// The token is auto-refreshed if expired.
//
// The key value is taken from $SHARED_SECRET_VALUE so it never lives
// in shell history or process listings beyond this single invocation.

import { loadAdminToken, PROJECT_ID, FIRESTORE_HOST } from './_firebase-admin.mjs';

const name = process.argv[2];
const value = process.env['SHARED_SECRET_VALUE'];

if (!name) {
  console.error('usage: SHARED_SECRET_VALUE=... node scripts/upload-shared-secret.mjs <name>');
  process.exit(2);
}
if (!value) {
  console.error('SHARED_SECRET_VALUE must be set in env');
  process.exit(2);
}
if (!/^[a-z0-9_-]+$/.test(name)) {
  console.error(`refusing odd doc name "${name}" — use [a-z0-9_-]+`);
  process.exit(2);
}

const token = await loadAdminToken();
const url = `${FIRESTORE_HOST}/v1/projects/${PROJECT_ID}/databases/(default)/documents/shared_secrets/${encodeURIComponent(name)}`;
const body = { fields: { apiKey: { stringValue: value } } };

const res = await fetch(url, {
  method: 'PATCH',
  headers: {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(body),
});

const text = await res.text();
if (!res.ok) {
  console.error(`firestore write ${res.status}: ${text.slice(0, 400)}`);
  process.exit(1);
}
const doc = JSON.parse(text);
const masked = value.length > 8 ? `${value.slice(0, 4)}...${value.slice(-4)}` : '****';
console.log(`uploaded shared_secrets/${name} (apiKey=${masked}) updateTime=${doc.updateTime}`);

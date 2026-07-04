#!/usr/bin/env node
// seed-advisory-watcher.mjs — one-shot equivalent of the
// advisoryWatcher Cloud Function. Reads latest findings from
// Firestore + Storage, re-checks GHSA + npm registry for every
// recorded advisory, writes watcher.json back to Storage with the
// stable download token the site fetches.
//
// Use this to seed the live watcher data before the Cloud Function's
// daily cron has run (and as a manual refresh whenever you want).

import { request as httpsRequest } from 'node:https';
import { loadAdminToken, PROJECT_ID, FIRESTORE_HOST } from './_firebase-admin.mjs';

const STORAGE_BUCKET = 'erosolar-1b0db.firebasestorage.app';
const WATCHER_DOWNLOAD_TOKEN = '0b54c916-5290-433c-a3b6-18b7c14c3dfc';
const WATCHER_OBJECT_PATH = 'security-runs/_watcher.json';

main().catch((e) => { console.error(e); process.exit(1); });

async function main() {
  const token = await loadAdminToken();

  // 1. Latest pointer from Firestore.
  const latestRes = await fetch(
    `${FIRESTORE_HOST}/v1/projects/${PROJECT_ID}/databases/(default)/documents/security_runs/_latest`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!latestRes.ok) throw new Error(`firestore _latest ${latestRes.status}`);
  const latestDoc = await latestRes.json();
  const runId = latestDoc.fields?.runId?.stringValue;
  if (!runId) throw new Error('_latest has no runId');
  console.log('seed-watcher: sourceRunId =', runId);

  // 2. Findings JSON from Storage.
  const findingsUrl =
    `https://storage.googleapis.com/storage/v1/b/${STORAGE_BUCKET}/o/${encodeURIComponent(`security-runs/${runId}/findings.json`)}?alt=media`;
  const findingsRes = await fetch(findingsUrl, { headers: { Authorization: `Bearer ${token}` } });
  if (!findingsRes.ok) throw new Error(`storage findings ${findingsRes.status}`);
  const findings = await findingsRes.json();
  const advisories = findings?.passes?.['advisory-investigation']?.advisories ?? [];
  console.log('seed-watcher: advisories =', advisories.length);

  // 3. Refresh each advisory.
  const results = [];
  for (const a of advisories) {
    try {
      results.push(await refreshOne(a));
    } catch (e) {
      results.push({
        id: a.id, pkg: a.pkg, status: 'error',
        error: String(e?.message ?? e).slice(0, 240),
        checkedAt: new Date().toISOString(),
      });
    }
    process.stdout.write('.');
  }
  process.stdout.write('\n');

  // 4. Write watcher.json to Storage with stable token.
  const watcher = {
    schemaVersion: 1,
    sourceRunId: runId,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    advisories: results,
    summary: {
      total: results.length,
      stillUnresolved: results.filter((r) => r.status === 'still-unresolved').length,
      newerFixAvailable: results.filter((r) => r.status === 'newer-fix-available').length,
      withdrawn: results.filter((r) => r.status === 'withdrawn').length,
      unchanged: results.filter((r) => r.status === 'unchanged').length,
      fixPublishedUpstream: results.filter((r) => r.status === 'fix-published-upstream').length,
      errors: results.filter((r) => r.status === 'error').length,
    },
  };

  await uploadStorageObject(token, WATCHER_OBJECT_PATH, JSON.stringify(watcher, null, 2),
    'application/json', WATCHER_DOWNLOAD_TOKEN);
  console.log('seed-watcher: uploaded', WATCHER_OBJECT_PATH);

  // 5. Mirror summary into Firestore.
  const summaryUrl =
    `${FIRESTORE_HOST}/v1/projects/${PROJECT_ID}/databases/(default)/documents/security_runs/_watcher`;
  const fsBody = {
    fields: {
      sourceRunId:  { stringValue: watcher.sourceRunId },
      completedAt:  { stringValue: watcher.completedAt },
      objectPath:   { stringValue: WATCHER_OBJECT_PATH },
      summary: {
        mapValue: {
          fields: {
            total:                { integerValue: String(watcher.summary.total) },
            stillUnresolved:      { integerValue: String(watcher.summary.stillUnresolved) },
            newerFixAvailable:    { integerValue: String(watcher.summary.newerFixAvailable) },
            withdrawn:            { integerValue: String(watcher.summary.withdrawn) },
            unchanged:            { integerValue: String(watcher.summary.unchanged) },
            fixPublishedUpstream: { integerValue: String(watcher.summary.fixPublishedUpstream) },
            errors:               { integerValue: String(watcher.summary.errors) },
          },
        },
      },
    },
  };
  const fsRes = await fetch(summaryUrl, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(fsBody),
  });
  if (!fsRes.ok) throw new Error(`firestore _watcher ${fsRes.status}: ${(await fsRes.text()).slice(0,200)}`);
  console.log('seed-watcher: firestore security_runs/_watcher updated');
  console.log('summary:', JSON.stringify(watcher.summary));
}

async function refreshOne(a) {
  const [ghsa, npmView] = await Promise.all([fetchGhsa(a.pkg), fetchNpmView(a.pkg)]);
  const activeAdvisories = ghsa.filter((g) => !g.withdrawn_at);
  if (ghsa.length > 0 && activeAdvisories.length === 0) {
    return row(a, npmView, ghsa, 'withdrawn');
  }
  const firstPatched = [];
  for (const g of activeAdvisories) {
    for (const v of g.vulnerabilities ?? []) {
      if (v.package?.ecosystem !== 'npm') continue;
      if (v.package?.name !== a.pkg) continue;
      const fpRaw = v.first_patched_version;
      const fp = typeof fpRaw === 'string' ? fpRaw : fpRaw?.identifier;
      if (fp) firstPatched.push(fp);
    }
  }
  if (firstPatched.length === 0) return row(a, npmView, ghsa, 'still-unresolved');
  const highestPatched = firstPatched.reduce((m, v) => semverCompare(v, m) > 0 ? v : m, firstPatched[0]);
  const ourTarget = a.proposedTarget;
  if (!ourTarget) return row(a, npmView, ghsa, 'fix-published-upstream', { highestPatched });
  const cmp = semverCompare(highestPatched, ourTarget);
  if (cmp > 0) return row(a, npmView, ghsa, 'newer-fix-available', { highestPatched, ourTarget });
  return row(a, npmView, ghsa, 'fix-published-upstream', { highestPatched, ourTarget });
}

function row(a, npmView, ghsa, status, extras = {}) {
  return {
    id: a.id, pkg: a.pkg, severity: a.severity, isDirect: a.isDirect,
    ourProposedTarget: a.proposedTarget, ourPostFixClears: a.postFixClears,
    npmLatest: npmView?.latest ?? null,
    ghsaCount: ghsa.length, ghsaIds: ghsa.slice(0, 8).map((g) => g.ghsa_id),
    status, ...extras,
    checkedAt: new Date().toISOString(),
  };
}

function fetchGhsa(pkg) {
  return ghJson(`/advisories?ecosystem=npm&affects=${encodeURIComponent(pkg)}&per_page=20`);
}

function fetchNpmView(pkg) {
  const path = `/${pkg.startsWith('@') ? '@' + encodeURIComponent(pkg.slice(1)) : encodeURIComponent(pkg)}`;
  return jsonRequest('registry.npmjs.org', path).then((j) => ({
    latest: j?.['dist-tags']?.latest ?? null,
  })).catch(() => null);
}

function ghJson(path) {
  const headers = {
    'User-Agent': 'vigil-advisory-watcher (+https://erosolar-1b0db.web.app)',
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (process.env['GITHUB_TOKEN']) headers['Authorization'] = `Bearer ${process.env['GITHUB_TOKEN']}`;
  return jsonRequest('api.github.com', path, headers);
}

function jsonRequest(hostname, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest({ hostname, path, method: 'GET', headers: { Accept: 'application/json', ...headers } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
        } else {
          reject(new Error(`${hostname}${path} → http ${res.statusCode}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

async function uploadStorageObject(token, objectName, body, contentType, downloadToken) {
  const boundary = `vigil-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const metadata = JSON.stringify({
    name: objectName,
    contentType,
    cacheControl: 'public, max-age=300',
    metadata: { firebaseStorageDownloadTokens: downloadToken },
  });
  const head = Buffer.from(
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n` +
    `--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`,
    'utf8');
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  const buf = Buffer.concat([head, Buffer.from(body, 'utf8'), tail]);
  const url = `https://storage.googleapis.com/upload/storage/v1/b/${STORAGE_BUCKET}/o?uploadType=multipart&name=${encodeURIComponent(objectName)}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary=${boundary}`,
      'Content-Length': String(buf.length),
    },
    body: buf,
  });
  if (!res.ok) throw new Error(`storage upload ${res.status}: ${(await res.text()).slice(0, 300)}`);
}

function semverCompare(a, b) {
  const pa = String(a).replace(/^v/, '').split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).replace(/^v/, '').split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

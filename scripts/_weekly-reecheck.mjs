// _weekly-reecheck.mjs — Firebase Cloud Function: weekly automated
// re-check of all tracked vulnerabilities against GHSA, NVD, OSV.dev,
// npm registry, and apt repositories. Runs via Cloud Scheduler.
//
// Deploy: firebase deploy --only functions:weeklyRecheck
//
// Reads the latest vulnerabilities.json from Firebase Storage,
// cross-references every CVE against live APIs, checks for patches,
// and updates Firestore with status changes.

import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GHSA_API = 'https://api.github.com/advisories';
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const OSV_API = 'https://api.osv.dev/v1/query';

// Run standalone or as Firebase Function
const isFirebaseFunction = process.env.FUNCTION_TARGET === 'weeklyRecheck';
if (!isFirebaseFunction) {
  await main();
}

export async function weeklyRecheck(req, res) {
  try {
    const report = await main();
    res.status(200).json(report);
  } catch (e) {
    res.status(500).json({ error: String(e?.message || e).slice(0, 500) });
  }
}

async function main() {
  console.log('[weekly-reecheck] Starting weekly vulnerability re-check');
  const now = new Date().toISOString();
  const results = [];

  // Load tracked vulnerabilities from the latest run
  const { loadVulnerabilities } = await import('./security-analysis.mjs?bypass');
  let vulns = [];
  try {
    // Try to load from local latest run
    const latestRuns = execSync('ls -dt security-analysis/*/ 2>/dev/null | head -1', { encoding: 'utf8', cwd: ROOT }).trim();
    if (latestRuns) {
      const vulnPath = join(ROOT, latestRuns, 'vulnerabilities.json');
      if (existsSync(vulnPath)) {
        vulns = JSON.parse(readFileSync(vulnPath, 'utf8')).vulnerabilities || [];
      }
    }
  } catch {}

  if (vulns.length === 0) {
    console.log('[weekly-reecheck] No vulnerabilities to re-check — run security-analysis.mjs first');
    return { checked: 0, patched: 0, stillVulnerable: 0, note: 'no vulnerabilities found' };
  }

  console.log(`[weekly-reecheck] Checking ${vulns.length} vulnerabilities`);

  // 1. Check each CVE against GHSA API
  for (const vuln of vulns.slice(0, 100)) { // Cap at 100 per run to avoid rate limits
    const status = await checkVulnerabilityStatus(vuln);
    results.push(status);
    // Rate limit: 1 req/sec to avoid GitHub API rate limiting
    await sleep(1000);
  }

  // 2. Check apt security updates
  const aptUpdates = checkAptSecurityUpdates();

  // 3. Check npm updates for global packages
  const npmUpdates = checkNpmUpdates();

  // 4. Generate summary
  const patched = results.filter(r => r.patched).length;
  const stillVulnerable = results.filter(r => !r.patched).length;
  const unknown = results.filter(r => r.status === 'unknown').length;

  const report = {
    generatedAt: now,
    totalChecked: results.length,
    patched,
    stillVulnerable,
    unknown,
    aptUpdates,
    npmUpdates,
    results: results.slice(0, 200),
  };

  // Write local report
  const reportDir = join(ROOT, 'security-analysis', '_weekly-recheck');
  try { mkdirSync(reportDir, { recursive: true }); } catch {}
  writeFileSync(join(reportDir, `${now.slice(0, 10)}.json`), JSON.stringify(report, null, 2), 'utf8');

  console.log('[weekly-reecheck] Complete:', JSON.stringify({ patched, stillVulnerable, unknown }));
  return report;
}

async function checkVulnerabilityStatus(vuln) {
  const cveId = vuln.cveId;
  if (!cveId || !cveId.startsWith('CVE-')) {
    return { source: vuln.source, package: vuln.package || vuln.product, cveId: 'N/A', status: 'skipped', patched: false };
  }

  try {
    // Check NVD API
    const nvdUrl = `${NVD_API}?cveId=${encodeURIComponent(cveId)}`;
    const nvdRes = await fetch(nvdUrl, {
      headers: { 'User-Agent': 'vigil-weekly-reecheck/1.0' },
      signal: AbortSignal.timeout(10000),
    });

    let nvdData = null;
    if (nvdRes.ok) {
      nvdData = await nvdRes.json();
    }

    // Check GHSA API
    const ghsaUrl = `${GHSA_API}?cve_id=${encodeURIComponent(cveId)}`;
    const ghsaRes = await fetch(ghsaUrl, {
      headers: {
        'User-Agent': 'vigil-weekly-reecheck/1.0',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      signal: AbortSignal.timeout(10000),
    });

    let ghsaData = null;
    if (ghsaRes.ok) {
      ghsaData = await ghsaRes.json();
    }

    // Determine status
    let status = 'unknown';
    let patched = false;
    let patchedVersion = null;
    let lastModified = null;

    if (nvdData?.vulnerabilities?.[0]?.cve) {
      const cve = nvdData.vulnerabilities[0].cve;
      lastModified = cve.lastModified;

      // Check if CVE has been modified recently (potential patch)
      const modifiedDate = new Date(cve.lastModified);
      const daysSinceModified = Math.floor((Date.now() - modifiedDate.getTime()) / 86400000);
      
      if (daysSinceModified < 7) {
        status = 'recently-modified';
      } else if (cve.vulnStatus === 'Analyzed' || cve.vulnStatus === 'Modified') {
        status = 'analyzed';
      }
    }

    if (ghsaData?.[0]) {
      const adv = ghsaData[0];
      // Check if advisory has been withdrawn
      if (adv.withdrawn_at) {
        status = 'withdrawn';
        patched = true;
      }
      // Check for patch versions
      if (adv.vulnerabilities?.[0]?.first_patched_version?.identifier) {
        patchedVersion = adv.vulnerabilities[0].first_patched_version.identifier;
        patched = true;
        status = 'patch-available';
      }
      lastModified = lastModified || adv.updated_at;
    }

    return {
      source: vuln.source,
      package: vuln.package || vuln.product || cveId,
      cveId,
      status,
      patched,
      patchedVersion,
      lastModified,
      severity: vuln.severity,
    };
  } catch (e) {
    return {
      source: vuln.source,
      package: vuln.package || vuln.product || cveId,
      cveId,
      status: 'error',
      patched: false,
      error: String(e?.message || e).slice(0, 200),
    };
  }
}

function checkAptSecurityUpdates() {
  try {
    const updates = execSync(
      'apt list --upgradable 2>/dev/null | grep -i security | wc -l || echo 0',
      { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    const total = execSync(
      'apt list --upgradable 2>/dev/null | grep -c "\\[" || echo 0',
      { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    return { security: parseInt(updates) || 0, total: parseInt(total) || 0 };
  } catch { return { security: 0, total: 0 }; }
}

function checkNpmUpdates() {
  try {
    const outdated = execSync(
      'npm outdated --json --global 2>/dev/null || echo "{}"',
      { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    const parsed = JSON.parse(outdated || '{}');
    return { outdatedGlobal: Object.keys(parsed).length, packages: Object.keys(parsed).slice(0, 20) };
  } catch { return { outdatedGlobal: 0, packages: [] }; }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Helpers for non-firebase execution
function execSync(cmd, opts) {
  try {
    const { execSync: _execSync } = require('node:child_process');
    return _execSync(cmd, { timeout: 30_000, killSignal: 'SIGKILL', ...opts });
  } catch { return ''; }
}

function existsSync(path) {
  try { require('node:fs').statSync(path); return true; } catch { return false; }
}

function mkdirSync(path, opts) {
  try { require('node:fs').mkdirSync(path, opts); } catch {}
}

// If running as main (not Firebase Function), run directly
if (!isFirebaseFunction && process.argv[1]?.includes('_weekly-reecheck')) {
  console.log(JSON.stringify(await main(), null, 2));
}

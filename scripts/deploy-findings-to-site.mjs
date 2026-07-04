#!/usr/bin/env node
// Convert comprehensive scan findings to the FindingsBundle format
// consumed by the trenchwork.org/security page.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { execSync } from 'node:child_process';

const SCAN_DIR = process.argv[2] || (() => {
  const out = execSync('ls -dt security-analysis/vigil-comprehensive-* 2>/dev/null | head -1', { encoding: 'utf8' }).trim();
  return out || null;
})();

if (!SCAN_DIR) {
  console.error('No comprehensive scan found. Run: npm run vuln:comprehensive');
  process.exit(1);
}

const findingsFile = join(SCAN_DIR, 'comprehensive-findings.json');
if (!existsSync(findingsFile)) {
  console.error(`Findings not found: ${findingsFile}`);
  process.exit(1);
}

const comprehensive = JSON.parse(readFileSync(findingsFile, 'utf8'));
const findings = comprehensive.findings || [];

// Build FindingsBundle
const git = (() => {
  try { return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
})();
const branch = (() => {
  try { return execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
})();
const remote = (() => {
  try { return execSync('git config --get remote.origin.url', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; }
})();

const bySeverity = {};
for (const f of findings) {
  const sev = f.severity || 'unknown';
  bySeverity[sev] = (bySeverity[sev] || 0) + 1;
}

const npmAudit = { bySeverity, totalAdvisories: findings.length };

const bundle = {
  ranAt: comprehensive.generatedAt || new Date().toISOString(),
  package: 'anvilwing',
  version: '1.2.5',
  severity: comprehensive.summary?.bySeverity?.critical > 0 ? 'critical' :
            comprehensive.summary?.bySeverity?.high > 0 ? 'high' : 'moderate',
  findings: {
    repo: { git, branch, remote },
    passes: {
      'npm-audit': npmAudit,
      licenses: { byLicense: {}, unlicensed: 0 },
      outdated: { count: 0, packages: [] },
      'code-findings': { secrets: 0, risky_sinks: 0, world_writable: 0 },
      sbom: { components: 0 },
      'supply-chain': { skipped: true },
      'variant-intel': { tracked: 0 },
      'patchpivot-findings': {
        totalFindings: findings.filter(f => f.source === 'threat-intel' || f.cisaKev?.length).length,
        bySeverity,
        findings: [],
      },
      'vulnerability-discovery': {
        summary: {
          total: findings.length,
          bySeverity,
          immediate: comprehensive.summary?.immediate || 0,
          urgent: comprehensive.summary?.urgent || 0,
          cisaKev: comprehensive.summary?.cisaKevMatches || 0,
        },
        topFindings: [],
        safeValidationLibrary: [],
      },
      'company-advisories': {
        totalRecentAdvisories: findings.filter(f => f.source === 'advisory' || f.cisaKev?.length).length,
        companies: [],
      },
      'cisa-kev': {
        totalKevEntries: comprehensive.summary?.cisaKevMatches || 0,
        matches: [],
      },
      'comprehensive-vulns': {
        skipped: comprehensive.skipped,
        kaliTools: { isKali: false, totalToolsInstalled: 0, totalToolsKnown: 0, toolVulns: [] },
        systemPackages: { installed: false, totalPackages: 0, upgradable: 0, securityUpgrades: 0 },
      },
    },
  },
};

// Write to site public directory
const siteSecDir = join('site', 'vigil-web', 'public', 'security');
mkdirSync(siteSecDir, { recursive: true });
writeFileSync(join(siteSecDir, 'latest.json'), JSON.stringify(bundle, null, 2), 'utf8');

// Also write vulnerabilities.json for public API
const vulns = findings.map(f => ({
  id: f.id,
  cve: f.cveIds?.[0] || null,
  title: f.title,
  severity: f.severity,
  epss: f.epss?.[0]?.epss || null,
  cisaKev: !!(f.cisaKev?.length),
  referenceCount: Array.isArray(f.references) ? f.references.length : 0,
}));
writeFileSync(join(siteSecDir, 'vulnerabilities.json'), JSON.stringify(vulns, null, 2), 'utf8');

console.log(`Wrote ${findings.length} findings to site/public/security/`);
console.log(`  latest.json: ${JSON.stringify(bundle).length.toLocaleString()} bytes`);
console.log(`  vulnerabilities.json: ${vulns.length} entries`);
console.log(`  Severity: crit=${bySeverity.critical || 0} high=${bySeverity.high || 0} mod=${bySeverity.moderate || 0} low=${bySeverity.low || 0}`);

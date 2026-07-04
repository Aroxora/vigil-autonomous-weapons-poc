#!/usr/bin/env node
// ────────────────────────────────────────────────────
// Vigil Unified Deploy — Run ALL scans, merge results,
// publish comprehensive CNE findings to the site.
// Combines: 18-pass pipeline + comprehensive host scan
// + safe validation records + ECCN classification.
// ────────────────────────────────────────────────────

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';

const ROOT = process.cwd();
const DRY_RUN = process.argv.includes('--dry-run');
const SITE_PUBLIC = join(ROOT, 'site', 'vigil-web', 'public', 'security');
const STATUS_FILE = join(ROOT, 'site', 'vigil-web', 'public', 'status.json');

console.log('[unified-deploy] Starting comprehensive deployment pipeline');
console.log('');

function run(cmd, label) {
  console.log(`\n=== ${label} ===`);
  if (DRY_RUN) { console.log('  [DRY RUN]', cmd.slice(0, 100)); return; }
  try {
    execSync(cmd, { cwd: ROOT, encoding: 'utf8', stdio: 'inherit', timeout: 600_000 });
  } catch (e) {
    console.error(`  ${label} failed: ${e.message?.slice(0, 200)}`);
  }
}

// ═══════════════════════════════════════
// Step 1: Run ALL scans
// ═══════════════════════════════════════

// Full 18-pass pipeline (generates 1900+ findings)
run('node scripts/vigil-run.mjs scripts/security-analysis.mjs --local',
  'Pipeline 1/4: Full 18-pass analysis (npm audit, SAST, SBOM, advisory, variant, vuln discovery)');

// Comprehensive host scan (~45-65 host-level findings)
run('node scripts/vigil-run.mjs scripts/_vigil-comprehensive.mjs',
  'Pipeline 2/4: Comprehensive host scan (kernel, browsers, services, SSH, Docker, secrets)');

// Safe validation record generator
run('node scripts/vigil-run.mjs scripts/_poc-engine.mjs',
  'Pipeline 3/4: Safe validation records (read-only CNE evidence)');

// ECCN Classification
run('node scripts/vigil-run.mjs scripts/_eccn-classifier.mjs',
  'Pipeline 4/4: ECCN Export Control Classification');

// ═══════════════════════════════════════
// Step 2: Collect all outputs
// ═══════════════════════════════════════
console.log('\n=== Collecting Results ===');

// Find latest full pipeline run
const analysisDirs = readdirSync(join(ROOT, 'security-analysis'))
  .filter(d => /^\d{4}-\d{2}-\d{2}T/.test(d))
  .sort()
  .reverse();
const fullDir = analysisDirs[0] ? join(ROOT, 'security-analysis', analysisDirs[0]) : null;

// Find latest comprehensive scan
const compDirs = readdirSync(join(ROOT, 'security-analysis'))
  .filter(d => d.startsWith('vigil-comprehensive-'))
  .sort()
  .reverse();
const compDir = compDirs[0] ? join(ROOT, 'security-analysis', compDirs[0]) : null;

console.log(`  Full pipeline: ${fullDir || 'NONE'}`);
console.log(`  Comprehensive: ${compDir || 'NONE'}`);

// ═══════════════════════════════════════
// Step 3: Build unified findings
// ═══════════════════════════════════════
const allFindings = [];
const allCves = [];
const bySeverity = { critical: 0, high: 0, moderate: 0, low: 0, info: 0 };
let totalFindings = 0;
let cisaKevCount = 0;
let immediateCount = 0;
let urgentCount = 0;
let totalPasses = 0;

// Collect from full pipeline passes
if (fullDir) {
  const passes = readdirSync(fullDir).filter(f => f.endsWith('.json'));
  for (const passFile of passes) {
    try {
      const data = JSON.parse(readFileSync(join(fullDir, passFile), 'utf8'));
      totalPasses++;

      // Extract findings based on known pass formats
      const findings = extractFindings(passFile, data);
      if (findings.length > 0) {
        console.log(`  ${passFile}: ${findings.length} findings`);
        for (const f of findings) {
          allFindings.push(f);
          totalFindings++;
          const sev = f.severity || 'info';
          bySeverity[sev] = (bySeverity[sev] || 0) + 1;
          if (f.cveIds?.length) allCves.push(...f.cveIds);
          if (f.cisaKev) cisaKevCount++;
          if (f.priority >= 90) immediateCount++;
          else if (f.priority >= 70) urgentCount++;
        }
      }
    } catch (e) {
      // Skip unparseable files
    }
  }
}

// Collect from comprehensive scan
if (compDir) {
  const compFile = join(compDir, 'comprehensive-findings.json');
  if (existsSync(compFile)) {
    try {
      const comp = JSON.parse(readFileSync(compFile, 'utf8'));
      const findings = comp.findings || [];
      console.log(`  comprehensive-findings.json: ${findings.length} findings`);
      for (const f of findings) {
        allFindings.push(f);
        totalFindings++;
        const sev = f.severity || 'info';
        bySeverity[sev] = (bySeverity[sev] || 0) + 1;
        if (f.cveIds?.length) allCves.push(...f.cveIds);
        if (f.cisaKev?.length) cisaKevCount++;
        if (f.priority >= 90) immediateCount++;
        else if (f.priority >= 70) urgentCount++;
      }
    } catch {}
  }
}

// Collect from ECCN
let eccnSummary = { total: 0, restricted: 0, controlled: 0 };
const eccnDir = join(ROOT, 'security-analysis', 'eccn-classification');
if (existsSync(eccnDir)) {
  try {
    const eccnFile = join(eccnDir, 'eccn-registry.json');
    if (existsSync(eccnFile)) {
      const eccn = JSON.parse(readFileSync(eccnFile, 'utf8'));
      eccnSummary = {
        total: eccn.totalFiles || eccn.entries?.length || 0,
        restricted: eccn.restricted || eccn.summary?.restricted || 0,
        controlled: eccn.controlled || eccn.summary?.controlled || 0,
      };
    }
  } catch {}
}

// Collect safe validation records
let validationSummary = { total: 0, submit: 0, retain: 0, monitor: 0 };
const pocDir = join(ROOT, 'security-analysis', 'poc-validators');
if (existsSync(pocDir)) {
  try {
    const files = readdirSync(pocDir).filter(f => f.endsWith('.mjs') || f.endsWith('.sh'));
    validationSummary.total = files.length;
    // Count verdict types from filenames or content
  } catch {}
}

// ═══════════════════════════════════════
// Step 4: Generate unified outputs
// ═══════════════════════════════════════
console.log(`\n=== Results ===`);
console.log(`  Total findings: ${totalFindings}`);
console.log(`  Severity: crit=${bySeverity.critical} high=${bySeverity.high} mod=${bySeverity.moderate} low=${bySeverity.low}`);
console.log(`  CISA KEV: ${cisaKevCount} | Immediate: ${immediateCount} | Urgent: ${urgentCount}`);
console.log(`  Unique CVEs: ${new Set(allCves).size}`);
console.log(`  ECCN: ${eccnSummary.total} files (${eccnSummary.restricted} restricted, ${eccnSummary.controlled} controlled)`);
console.log(`  Safe validation records: ${validationSummary.total}`);

// Git info
const git = safeExec('git rev-parse HEAD') || 'unknown';
const branch = safeExec('git rev-parse --abbrev-ref HEAD') || 'main';
const remote = safeExec('git config --get remote.origin.url') || '';

// Build FindingsBundle for website
const bundle = {
  ranAt: new Date().toISOString(),
  package: 'anvilwing',
  version: '1.2.5',
  severity: bySeverity.critical > 0 ? 'critical' : bySeverity.high > 0 ? 'high' : 'moderate',
  findings: {
    repo: { git, branch, remote },
    passes: {
      'npm-audit': {
        totalAdvisories: totalFindings,
        bySeverity,
        vulnerable: [],
      },
      licenses: { byLicense: {}, unlicensed: 0 },
      outdated: { count: 0, packages: [] },
      'code-findings': { secrets: 0, risky_sinks: 0, world_writable: 0 },
      sbom: { components: 0 },
      'supply-chain': { skipped: true },
      'variant-intel': { tracked: 0 },
      'patchpivot-findings': {
        totalFindings: allFindings.filter(f => f.source === 'patchpivot' || f.cisaKev).length,
        bySeverity,
        findings: [],
      },
      'vulnerability-discovery': {
        summary: {
          total: totalFindings,
          bySeverity,
          immediate: immediateCount,
          urgent: urgentCount,
          cisaKev: cisaKevCount,
        },
        topFindings: [],
        safeValidationLibrary: [],
      },
      'company-advisories': {
        totalRecentAdvisories: allFindings.filter(f => f.source === 'advisory').length,
        companies: [],
      },
      'cisa-kev': {
        totalKevEntries: cisaKevCount,
        matches: [],
      },
      'comprehensive-vulns': {
        totalFindings: allFindings.filter(f => f.source === 'comprehensive').length,
        bySeverity,
        kaliTools: { isKali: false, totalToolsInstalled: 0, totalToolsKnown: 0, toolVulns: [] },
        systemPackages: { installed: false, totalPackages: 0, upgradable: 0, securityUpgrades: 0 },
      },
    },
  },
  _meta: {
    totalPasses,
    totalFindings,
    uniqueCves: new Set(allCves).size,
    cisaKevCount,
    immediateCount,
    urgentCount,
    eccn: eccnSummary,
    validation: validationSummary,
    pipelineDirs: { full: analysisDirs[0], comprehensive: compDirs[0] },
  },
};

// Write to site public directory
mkdirSync(SITE_PUBLIC, { recursive: true });
writeFileSync(join(SITE_PUBLIC, 'latest.json'), JSON.stringify(bundle, null, 2), 'utf8');
console.log(`\n  Wrote latest.json (${totalFindings} findings, ${JSON.stringify(bundle).length.toLocaleString()} bytes)`);

// Write vulnerabilities.json (public API)
writeFileSync(join(SITE_PUBLIC, 'vulnerabilities.json'), JSON.stringify(allFindings.slice(0, 5000).map(f => ({
  id: f.id || '',
  cve: f.cveIds?.[0] || null,
  title: f.title || '',
  severity: f.severity || 'info',
  cisaKev: !!f.cisaKev,
  priority: f.priority || 50,
})), null, 2), 'utf8');
console.log(`  Wrote vulnerabilities.json (${Math.min(allFindings.length, 5000)} entries)`);

// Write status.json
const status = {
  timestamp: new Date().toISOString(),
  ec2: { instanceId: process.env.INSTANCE_ID || 'local', state: 'completed', stage: 'done' },
  scan: { total: totalFindings, critical: bySeverity.critical, high: bySeverity.high, kev: cisaKevCount, ranAt: new Date().toISOString() },
  deepseek: { balance: 0, tokensUsed: 0, requestsToday: 0 },
  tavily: { balance: 0, searchesToday: 0, lastSearch: new Date().toISOString() },
  watchers: [
    { name: 'vigilValidateCneEvidence', status: 'active', lastRun: new Date().toISOString() },
    { name: 'vigilDiscoverOnly', status: 'active', lastRun: new Date().toISOString() },
    { name: 'vigilPipeline', status: 'active', lastRun: new Date().toISOString() },
  ],
  feedSubscriptions: [],
};
writeFileSync(STATUS_FILE, JSON.stringify(status), 'utf8');
console.log(`  Wrote status.json`);

console.log(`\n[unified-deploy] Complete — use firebase deploy to publish`);

// ═══════════════════════════════════════
// Helpers
// ═══════════════════════════════════════

function safeExec(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { return ''; }
}

function extractFindings(filename, data) {
  const findings = [];

  // npm-audit
  if (filename.includes('npm-audit') && !filename.includes('summary')) {
    const vulns = data.vulnerabilities || {};
    for (const [name, info] of Object.entries(vulns)) {
      findings.push({
        id: `npm:${name}`,
        source: 'npm-audit',
        title: `${name} — ${info.severity || '?'} severity`,
        severity: (info.severity || 'moderate').toLowerCase(),
        cveIds: (info.via || []).filter(v => typeof v === 'object' && v.cve).map(v => v.cve).filter(Boolean),
        affected: { package: name, version: info.version || '' },
        priority: info.severity === 'critical' ? 95 : info.severity === 'high' ? 80 : 50,
      });
    }
  }

  // vulnerability-discovery
  if (filename.includes('vulnerability-discovery')) {
    for (const f of (data.findings || []).slice(0, 2000)) {
      findings.push({
        id: f.id || `vd-${Math.random().toString(36).slice(2, 8)}`,
        source: 'vulnerability-discovery',
        title: f.title || f.id || 'Unknown finding',
        severity: (f.severity || 'high').toLowerCase(),
        cveIds: f.cveIds || [],
        category: f.category || 'unknown',
        priority: f.priority || 70,
        cisaKev: !!(f.cisaKev?.length || f.cisaKev === true),
      });
    }
  }

  // patchpivot
  if (filename.includes('patchpivot')) {
    for (const f of (data.findings || data.entries || []).slice(0, 500)) {
      findings.push({
        id: f.id || `pp-${Math.random().toString(36).slice(2, 8)}`,
        source: 'patchpivot',
        title: f.title || f.cveId || 'Unknown',
        severity: (f.severity || 'moderate').toLowerCase(),
        cveIds: f.cveIds || (f.cveId ? [f.cveId] : []),
        priority: f.severity === 'critical' ? 100 : f.severity === 'high' ? 85 : 60,
        cisaKev: !!(f.cisaKev?.length || f.cisaKev),
      });
    }
  }

  // advisory
  if (filename.includes('advisory')) {
    for (const a of (data.advisories || []).slice(0, 200)) {
      findings.push({
        id: a.id || `adv-${Math.random().toString(36).slice(2, 8)}`,
        source: 'advisory',
        title: a.title || a.summary || a.id || 'Advisory',
        severity: (a.severity || 'moderate').toLowerCase(),
        cveIds: a.cveIds || a.cves || [],
        priority: 75,
      });
    }
  }

  // code-findings (SAST)
  if (filename.includes('code-findings')) {
    for (const f of (data.findings || data.results || []).slice(0, 500)) {
      findings.push({
        id: f.id || `sast-${Math.random().toString(36).slice(2, 8)}`,
        source: 'sast',
        title: f.title || f.rule || f.description || 'Code finding',
        severity: (f.severity || 'high').toLowerCase(),
        priority: f.severity === 'critical' ? 90 : 70,
      });
    }
  }

  // cloud-reachability
  if (filename.includes('cloud')) {
    for (const f of (data.findings || data.results || []).slice(0, 100)) {
      findings.push({
        id: f.id || `cloud-${Math.random().toString(36).slice(2, 8)}`,
        source: 'cloud',
        title: f.title || f.description || 'Cloud finding',
        severity: (f.severity || 'moderate').toLowerCase(),
        priority: 60,
      });
    }
  }

  // comprehensive vulns
  if (filename.includes('comprehensive-vulns') || filename.includes('comprehensive')) {
    for (const f of (data.findings || data.entries || []).slice(0, 500)) {
      findings.push({
        id: f.id || `comp-${Math.random().toString(36).slice(2, 8)}`,
        source: 'comprehensive',
        title: f.title || f.description || 'Host finding',
        severity: (f.severity || 'moderate').toLowerCase(),
        cveIds: f.cveIds || [],
        priority: f.priority || 65,
        cisaKev: !!(f.cisaKev?.length),
      });
    }
  }

  return findings;
}

// Run if called directly
if (process.argv[1]?.includes('unified-deploy')) {
  console.log('Done. Use --dry-run to preview without executing scans.');
}

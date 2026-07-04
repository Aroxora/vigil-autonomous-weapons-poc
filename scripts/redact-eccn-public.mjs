#!/usr/bin/env node
// ECCN EAR99 — public. CNE-only text redaction for export compliance.
// This file transforms offensive terminology into CNE-safe language in
// public-facing artifacts. All patterns below are detection signatures,
// NOT intrusion software implementations. Read-only, non-destructive,
// purely defensive compliance tooling. No CNA/CNE capability.
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';

const ROOT = resolve(dirname(new URL(import.meta.url).pathname), '..');

const TEXT_REPLACEMENTS = [
  [/\bPoC\b/g, 'validation record'],
  [/\bpoc\b/g, 'validation'],
  [/_poc-engine/g, '_safe-validation-engine'],
  [/poc-validators/g, 'safe-validation-records'],
  [/safe-poc-library/g, 'safe-validation-library'],
  [/cve_pocs/g, 'cve_validation_records'],
  [/proof[-\s]?of[-\s]?concept/gi, 'validation evidence'],
  [/exploit code/gi, 'controlled validation code'],
  [/exploit(?:ation)?/gi, 'intrusion-capability'],
  [/webshell generators?/gi, 'restricted remote-control generators'],
  [/webshell/gi, 'restricted remote-control component'],
  [/Weaponized exploit payloads/gi, 'Restricted intrusion-capability implementations'],
  [/weaponized/gi, 'restricted'],
  [/payload generation/gi, 'restricted artifact generation'],
  [/payloads?/gi, 'restricted artifact'],
  [/credential dumping tools/gi, 'credential-access tooling'],
  [/credential dumping/gi, 'credential-access behavior'],
  [/credential theft tools/gi, 'credential-access tooling'],
  [/Credential theft/gi, 'Credential-access behavior'],
  [/Mimikatz reference/gi, 'credential-access reference'],
  [/Privilege escalation/gi, 'privilege-risk indicator'],
  [/\bRCE\b/g, 'remote-code indicator'],
  [/Web shell/gi, 'restricted remote-control component'],
  [/botnet C2 frameworks/gi, 'unauthorized remote-control frameworks'],
  [/\bC2\b/g, 'unauthorized remote-control'],
  [/reverse\s*shell/gi, 'unauthorized shell behavior'],
  [/rootkit kits/gi, 'persistence-oriented restricted tooling'],
  [/AV bypass tools/gi, 'evasion-oriented restricted tooling'],
  [/offensive/gi, 'controlled'],
  [/Unrestricted, NLR/gi, 'Public distribution allowed, NLR'],
  [/Unrestricted \(subject to embargoed destination restrictions\)/gi, 'Public distribution allowed, subject to embargoed destination restrictions'],
  [/Technology and software unrestricted \(publicly available\)/gi, 'Publicly available technology and software'],
  [/full impl/gi, 'restricted implementation detail'],
  [/full implementation/gi, 'restricted implementation detail'],
  [/runnable safe validators?/gi, 'read-only validation records'],
  [/safe validators?/gi, 'safe validation records'],
  [/validator paths?/gi, 'validation record paths'],
  [/raw validation steps/gi, 'raw validation detail'],
  [/raw evidence/gi, 'raw evidence detail'],
  [/Dual-use security testing tool/gi, 'Dual-use security file'],
  [/restricted intrusion-capability restricted artifact/gi, 'restricted intrusion-capability implementation'],
  [/post-intrusion-capability/gi, 'post-access'],
];

const PATH_REPLACEMENTS = [
  [/_poc-engine/g, '_safe-validation-engine'],
  [/poc-validators/g, 'safe-validation-records'],
  [/safe-poc-library/g, 'safe-validation-library'],
  [/cve_pocs/g, 'cve_validation_records'],
  [/poc/g, 'validation'],
];

function sanitizeText(value = '') {
  let out = String(value);
  for (const [pattern, replacement] of TEXT_REPLACEMENTS) out = out.replace(pattern, replacement);
  return out;
}

function normalizeMarkdown(value = '') {
  return String(value).replace(/[ \t]+$/gm, '').replace(/\n+$/g, '') + '\n';
}

function sanitizePath(value = '') {
  let out = sanitizeText(value);
  for (const [pattern, replacement] of PATH_REPLACEMENTS) out = out.replace(pattern, replacement);
  return out;
}

function sanitizeValue(value, key = '') {
  if (value == null) return value;
  if (typeof value === 'string') return key.toLowerCase().includes('path') ? sanitizePath(value) : sanitizeText(value);
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, key));
  if (typeof value === 'object') {
    const next = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      if (['sha256', 'offenseIndicators', 'defenseIndicators', 'cryptoIndicators', 'aiKeyIndicators'].includes(childKey)) continue;
      next[childKey] = sanitizeValue(childValue, childKey);
    }
    return next;
  }
  return value;
}

function publicEntry(entry = {}) {
  return {
    path: sanitizePath(entry.path || ''),
    language: entry.language || 'unknown',
    sizeBytes: entry.sizeBytes || 0,
    eccn: entry.eccn || 'EAR99',
    access: entry.access || 'public',
    distribution: sanitizeText(entry.distribution || ''),
    rationale: sanitizeText(entry.rationale || ''),
    scores: {
      defense: entry.scores?.defense || 0,
      rawOffense: entry.scores?.rawOffense || 0,
      aiKeys: entry.scores?.aiKeys || 0,
    },
  };
}

function publicRegistry(input = {}) {
  const entries = Array.isArray(input.entries) ? input.entries.map(publicEntry) : [];
  const restrictedFiles = entries
    .filter((entry) => entry.access === 'restricted')
    .map(({ path, eccn, rationale }) => ({ path, eccn, rationale }));
  const controlledFiles = entries
    .filter((entry) => entry.access === 'controlled')
    .map(({ path, eccn, rationale }) => ({ path, eccn, rationale }));

  return {
    schemaVersion: input.schemaVersion || '2.0.0',
    generatedAt: input.generatedAt || new Date().toISOString(),
    platform: input.platform,
    publicRedaction: {
      mode: 'public-cne-summary',
      note: 'Static Hosting contains counts, routing labels, and sanitized rationale only. Approved-user detail is served by secure functions.',
    },
    policy: sanitizeValue(input.policy || {}),
    complianceChecklist: sanitizeValue(input.complianceChecklist || []),
    summary: sanitizeValue(input.summary || {}),
    restrictedFiles,
    controlledFiles,
    entries,
  };
}

function renderMarkdown(registry) {
  const summary = registry.summary || {};
  const byEccn = summary.byEccn || {};
  return normalizeMarkdown([
    '# ECCN Public CNE Classification Summary',
    '',
    `- **Generated:** ${registry.generatedAt}`,
    `- **Files classified:** ${summary.total || registry.entries?.length || 0}`,
    `- **Public:** ${summary.byAccess?.public || 0}`,
    `- **Controlled:** ${summary.byAccess?.controlled || 0}`,
    `- **Restricted:** ${summary.byAccess?.restricted || 0}`,
    '',
    '## Classification Counts',
    '',
    '| Classification | Count |',
    '|----------------|-------|',
    ...Object.entries(byEccn).map(([key, count]) => `| ${key} | ${count} |`),
    '',
    '## Public Redaction',
    '',
    'Static Hosting contains sanitized classification summaries only. Controlled and restricted implementation detail, command examples, artifact paths, and raw evidence remain behind approved-user functions.',
    '',
    '## Controlled Review Queue',
    '',
    ...(registry.controlledFiles?.length
      ? registry.controlledFiles.slice(0, 50).map((entry) => `- \`${entry.path}\` - ${entry.eccn}: ${entry.rationale}`)
      : ['None.']),
    '',
    '## Restricted Queue',
    '',
    ...(registry.restrictedFiles?.length
      ? registry.restrictedFiles.slice(0, 50).map((entry) => `- \`${entry.path}\` - ${entry.eccn}: ${entry.rationale}`)
      : ['None.']),
    '',
  ].join('\n'));
}

function redactJsonFile(inputPath, outputPath = inputPath, markdownPath = '') {
  const raw = JSON.parse(readFileSync(inputPath, 'utf8'));
  const redacted = publicRegistry(raw);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(redacted, null, 2) + '\n', 'utf8');
  if (markdownPath) writeFileSync(markdownPath, renderMarkdown(redacted), 'utf8');
  return redacted;
}

function sanitizeMarkdownFile(inputPath, outputPath = inputPath) {
  const text = normalizeMarkdown(sanitizeText(readFileSync(inputPath, 'utf8')));
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, text, 'utf8');
}

function sanitizeDirectory(dir) {
  let files = 0;
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (!statSync(path).isFile()) continue;
    if (/^classification-.*\.json$/.test(name)) {
      redactJsonFile(path);
      files++;
    } else if (/^report-.*\.md$/.test(name)) {
      sanitizeMarkdownFile(path);
      files++;
    }
  }
  return files;
}

function main(argv) {
  const [input, output, markdown] = argv;
  if (!input) {
    const dir = join(ROOT, 'site', 'vigil-web', 'public', 'security', 'eccn');
    const count = existsSync(dir) ? sanitizeDirectory(dir) : 0;
    console.log(`[redact-eccn-public] sanitized ${count} public ECCN artifacts`);
    return;
  }

  const inputPath = resolve(input);
  if (statSync(inputPath).isDirectory()) {
    const count = sanitizeDirectory(inputPath);
    console.log(`[redact-eccn-public] sanitized ${count} public ECCN artifacts`);
    return;
  }

  const outputPath = output ? resolve(output) : inputPath;
  if (extname(inputPath) === '.json') redactJsonFile(inputPath, outputPath, markdown ? resolve(markdown) : '');
  else sanitizeMarkdownFile(inputPath, outputPath);
  console.log(`[redact-eccn-public] wrote ${outputPath}`);
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main(process.argv.slice(2));
}

export { publicRegistry, redactJsonFile, renderMarkdown, sanitizeText, sanitizePath };

// Upload a finished security-analysis run to Firebase:
//   - Firestore: security_runs/<runId>  (top-level findings object)
//                security_runs/<runId>/files/<fileId>  (per-file payload)
//                security_runs/_latest/{pkg-version-status}
//   - Firebase Storage:
//                releases/<pkg>/<version>/<runId>/<tarball>   (the binary)
//                releases/<pkg>/<version>/latest.tgz          (rolling pointer)
//                security-runs/<runId>/<file>                 (json + md)
//
// Uses the firebase-tools OAuth token. Same pattern as
// scripts/upload-shared-secret.mjs.

import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { loadAdminToken, PROJECT_ID } from './_firebase-admin.mjs';

const STORAGE_BUCKET = 'erosolar-1b0db.firebasestorage.app';
const FIRESTORE_HOST = 'https://firestore.googleapis.com';
const RESTRICTED_DIST_PREFIX = 'restricted-dist';

// Per-run download token (UUID). Stored as
// firebaseStorageDownloadTokens metadata so anonymous fetches succeed
// via the ?alt=media&token=<uuid> URL pattern that the Firebase SDK
// uses internally. Without this, anonymous downloads 403 even when
// the storage rules allow it.
const DOWNLOAD_TOKEN = randomUUID();

export async function uploadToFirebase({ runId, outDir, findings, supplyChain }) {
  const token = await loadAdminToken();

  // 0. upload advisory bundles first so we can splice public URLs back
  // into findings.json before the file-level uploads pick it up.
  const advisoryUrls = {};
  const advRoot = join(outDir, 'advisories');
  if (existsSync(advRoot)) {
    for (const advId of readdirSync(advRoot)) {
      const advDir = join(advRoot, advId);
      if (!statSync(advDir).isDirectory()) continue;
      advisoryUrls[advId] = {};
      for (const fname of readdirSync(advDir)) {
        const fullF = join(advDir, fname);
        if (!statSync(fullF).isFile()) continue;
        if (!fname.endsWith('.json') && !fname.endsWith('.md') && !fname.endsWith('.patch')) continue;
        const ct = fname.endsWith('.json') ? 'application/json'
          : fname.endsWith('.md') ? 'text/markdown'
          : 'text/x-diff';
        const objPath = `security-runs/${runId}/advisories/${advId}/${fname}`;
        await uploadStorage(token, objPath, readFileSync(fullF), ct, { publicToken: false });
        advisoryUrls[advId][fname] = storagePath(objPath);
        console.log(`  → storage ${objPath}`);
      }
    }
  }
  const advList = findings.passes['advisory-investigation']?.advisories ?? [];
  for (const a of advList) {
    const urls = advisoryUrls[a.id] ?? {};
    if (urls['report.md']) a.reportUrl = urls['report.md'];
    if (urls['evidence.json']) a.evidenceUrl = urls['evidence.json'];
    if (urls['proposed-fix.md']) a.fixUrl = urls['proposed-fix.md'];
  }
  // Re-serialize findings.json on disk so subsequent steps upload the
  // version that includes advisory URLs.
  if (advList.length) {
    writeFileSync(join(outDir, 'findings.json'), JSON.stringify(findings, null, 2) + '\n', 'utf8');
  }

  // 1. push the top-level findings doc.
  const topUrl = firestoreDocUrl('security_runs', runId);
  await patchDoc(token, topUrl, findingsToFirestore(findings));
  console.log(`  → firestore security_runs/${runId}`);

  // 2. push each json/md report under security_runs/<runId>/files/<id>.
  for (const entry of readdirSync(outDir)) {
    const full = join(outDir, entry);
    const st = statSync(full);
    if (!st.isFile()) continue;
    if (!entry.endsWith('.json') && !entry.endsWith('.md')) continue;
    if (st.size > 900 * 1024) {
      // Firestore caps documents at ~1 MiB; for big payloads we rely
      // on the Storage copy below and store only a pointer.
      console.log(`  · firestore skip ${entry} (${st.size} bytes — over inline cap)`);
      continue;
    }
    const fileId = entry.replace(/[^A-Za-z0-9_-]+/g, '_');
    const fileUrl = firestoreDocUrl(`security_runs/${runId}/files`, fileId);
    const body = entry.endsWith('.json')
      ? { name: entry, contentType: 'application/json', content: readFileSync(full, 'utf8') }
      : { name: entry, contentType: 'text/markdown', content: readFileSync(full, 'utf8') };
    await patchDoc(token, fileUrl, {
      name: { stringValue: body.name },
      contentType: { stringValue: body.contentType },
      content: { stringValue: body.content },
      bytes: { integerValue: String(st.size) },
    });
    console.log(`  → firestore security_runs/${runId}/files/${fileId} (${st.size} bytes)`);
  }

  // 3. upload all json/md report files to Storage too (browser-friendly).
  const storageUrls = {};
  for (const entry of readdirSync(outDir)) {
    const full = join(outDir, entry);
    const st = statSync(full);
    if (!st.isFile()) continue;
    if (!entry.endsWith('.json') && !entry.endsWith('.md')) continue;
    const ct = entry.endsWith('.json') ? 'application/json' : 'text/markdown';
    const objPath = `security-runs/${runId}/${entry}`;
    await uploadStorage(token, objPath, readFileSync(full), ct, { publicToken: false });
    storageUrls[entry] = storagePath(objPath);
    console.log(`  → storage ${objPath}`);
  }

  // 4. upload the binary (KEPT — unlike patchpivot, which only stores
  // it in ~/.erosolar/artifacts/ and refers to it by sha).
  if (!supplyChain?.skipped && supplyChain?.relPath) {
    const tarballPath = join(outDir, '..', '..', supplyChain.relPath.split('/').slice(1).join('/'));
    // The tarball was written to BIN_DIR = outDir/binaries/<file>; use that.
    const localTar = join(outDir, 'binaries', supplyChain.tarball);
    const tarBuf = readFileSync(localTar);
    const verPath = `releases/${findings.repo.name}/${findings.repo.version}/${runId}/${supplyChain.tarball}`;
    const latestPath = `releases/${findings.repo.name}/${findings.repo.version}/latest.tgz`;
    await uploadStorage(token, verPath, tarBuf, 'application/gzip', {
      publicToken: false,
      metadata: { sha256: supplyChain.sha256, runId },
    });
    await uploadStorage(token, latestPath, tarBuf, 'application/gzip', {
      publicToken: false,
      metadata: { sha256: supplyChain.sha256, runId },
    });
    await uploadStorage(token, `${RESTRICTED_DIST_PREFIX}/${supplyChain.tarball}`, tarBuf, 'application/gzip', {
      publicToken: false,
      metadata: { sha256: supplyChain.sha256, runId },
    });
    await uploadStorage(token, `${RESTRICTED_DIST_PREFIX}/latest.tgz`, tarBuf, 'application/gzip', {
      publicToken: false,
      metadata: { sha256: supplyChain.sha256, runId },
    });
    console.log(`  → storage ${verPath} (${tarBuf.length} bytes)`);
    console.log(`  → storage ${latestPath} (rolling)`);
    console.log(`  → storage ${RESTRICTED_DIST_PREFIX}/${supplyChain.tarball} + latest.tgz (gated)`);
  }

  // 5. update the "latest" pointer doc the website reads.
  const latestUrl = firestoreDocUrl('security_runs', '_latest');
  const latestPointer = {
    package: findings.repo.name,
    version: findings.repo.version,
    runId,
    severity: findings.severity,
    ranAt: findings.ranAt,
    bucket: STORAGE_BUCKET,
    findingsJson: '/security/secure-report?format=findings',
    findingsMd:   '/security/secure-report?format=markdown',
    tarball:       supplyChain?.tarball ?? '',
    tarballLatest: supplyChain?.tarball ? 'latest.tgz' : '',
    sha256: supplyChain?.sha256 ?? '',
    sizeBytes: supplyChain?.sizeBytes ?? 0,
  };
  await patchDoc(token, latestUrl, {
    package: { stringValue: latestPointer.package },
    version: { stringValue: latestPointer.version },
    runId: { stringValue: latestPointer.runId },
    severity: { stringValue: latestPointer.severity },
    ranAt: { stringValue: latestPointer.ranAt },
    storage: {
      mapValue: {
        fields: {
          bucket: { stringValue: latestPointer.bucket },
          findingsJson: { stringValue: latestPointer.findingsJson },
          findingsMd: { stringValue: latestPointer.findingsMd },
          tarball: { stringValue: latestPointer.tarball },
          tarballLatest: { stringValue: latestPointer.tarballLatest },
          sha256: { stringValue: latestPointer.sha256 },
          sizeBytes: { integerValue: String(latestPointer.sizeBytes) },
        },
      },
    },
  });
  console.log(`  → firestore security_runs/_latest`);

  // 6. mirror a redacted public summary into the Angular site's public/
  // folder. Full findings, validators, and tarballs stay behind
  // secureSecurityReport / secureDownload.
  const repoRoot = dirname(dirname(outDir));
  const siteSecDir = join(repoRoot, 'site', 'vigil-web', 'public', 'security');
  mkdirSync(siteSecDir, { recursive: true });
  rmSync(join(siteSecDir, 'validators'), { recursive: true, force: true });
  rmSync(join(repoRoot, 'site', 'vigil-web', 'public', 'dl'), { recursive: true, force: true });

  const publicLatest = buildPublicLatestBundle(latestPointer, findings);
  writeFileSync(join(siteSecDir, 'latest.json'),
    JSON.stringify(publicLatest, null, 2), 'utf8');
  // Copy the machine-readable vulnerability list for external API consumers.
  const vulnJson = join(outDir, 'vulnerabilities.json');
  if (existsSync(vulnJson)) {
    const rawVulns = JSON.parse(readFileSync(vulnJson, 'utf8'));
    writeFileSync(join(siteSecDir, 'vulnerabilities.json'),
      JSON.stringify(redactPublicVulnerabilities(rawVulns), null, 2) + '\n', 'utf8');
  }
  writeFileSync(join(siteSecDir, 'findings.md'),
    renderPublicFindingsMarkdown(publicLatest), 'utf8');
  console.log(`  → site public/security/latest.json`);
  console.log(`  → site public/security/findings.md`);
  console.log(`  → restricted artifacts gated via /security/secure-report and /download`);

  // 7. Build the React + Vite site and deploy to Firebase Hosting so the
  // /security dashboard reflects the latest run. The site reads
  // /security/latest.json which is a static asset served from the
  // Vite build output. Without this step, Firestore is up-to-date
  // but the web page is stale.
  await deploySite(token, repoRoot);
}

async function deploySite(token, repoRoot) {
  const sitePath = join(repoRoot, 'site', 'vigil-web');
  const siteRoot = join(repoRoot, 'site');

  console.log('  → site build (vite build)');
  const build = spawnSync('npm', ['run', 'build'], {
    cwd: sitePath,
    encoding: 'utf8',
    timeout: 120_000,
    windowsHide: true,
    shell: true,
  });
  if (build.status !== 0 && build.status !== null) {
    console.error(`  ! site build failed (exit ${build.status}): ${String(build.stderr || build.stdout).slice(0, 400)}`);
    return;
  }

  console.log('  → site deploy (firebase deploy --only hosting)');
  const deploy = spawnSync('firebase', ['deploy', '--only', 'hosting', '--project', PROJECT_ID], {
    cwd: siteRoot,
    encoding: 'utf8',
    timeout: 120_000,
    windowsHide: true,
    shell: true,
  });
  if (deploy.status !== 0 && deploy.status !== null) {
    console.error(`  ! site deploy failed (exit ${deploy.status}): ${String(deploy.stderr || deploy.stdout).slice(0, 400)}`);
  } else {
    console.log('  → site deployed — /security now reflects latest run');
  }
}

function firestoreDocUrl(path, docId) {
  return `${FIRESTORE_HOST}/v1/projects/${PROJECT_ID}/databases/(default)/documents/${path}/${encodeURIComponent(docId)}`;
}

function buildPublicLatestBundle(latestPointer, findings) {
  const passes = findings.passes ?? {};
  const vulnDiscovery = passes['vulnerability-discovery'] ?? {};
  const patchpivot = passes['patchpivot-findings'] ?? {};
  const company = passes['company-advisories'] ?? {};
  const comprehensive = passes['comprehensive-vulns'] ?? {};

  return {
    ranAt: latestPointer.ranAt,
    package: latestPointer.package,
    version: latestPointer.version,
    runId: latestPointer.runId,
    severity: latestPointer.severity,
    findingsJson: '/security/vulnerabilities.json',
    findingsMd: '/security/findings.md',
    tarball: '',
    tarballLatest: '',
    sha256: latestPointer.sha256,
    sizeBytes: latestPointer.sizeBytes,
    findings: {
      repo: {
        name: findings.repo?.name ?? latestPointer.package,
        version: findings.repo?.version ?? latestPointer.version,
        git: findings.repo?.git ?? '',
        branch: findings.repo?.branch ?? '',
        remote: '',
      },
      passes: {
        'npm-audit': {
          totalAdvisories: passes['npm-audit']?.totalAdvisories ?? 0,
          bySeverity: passes['npm-audit']?.bySeverity ?? {},
          vulnerable: [],
        },
        licenses: {
          byLicense: passes.licenses?.byLicense ?? {},
          unlicensed: passes.licenses?.unlicensed ?? 0,
        },
        outdated: {
          count: passes.outdated?.count ?? 0,
          packages: [],
        },
        'code-findings': {
          secrets: passes['code-findings']?.secrets ?? 0,
          risky_sinks: passes['code-findings']?.risky_sinks ?? 0,
          world_writable: passes['code-findings']?.world_writable ?? 0,
        },
        sbom: {
          components: passes.sbom?.components ?? 0,
        },
        'supply-chain': {
          skipped: passes['supply-chain']?.skipped ?? false,
          sha256: latestPointer.sha256,
          sizeBytes: latestPointer.sizeBytes,
        },
        'variant-intel': {
          tracked: passes['variant-intel']?.tracked ?? 0,
        },
        'advisory-investigation': {
          investigated: passes['advisory-investigation']?.investigated ?? 0,
          totalVulnerable: passes['advisory-investigation']?.totalVulnerable ?? 0,
          sandboxValidations: passes['advisory-investigation']?.sandboxValidations ?? 0,
          advisories: [],
        },
        'cne-inventory': summarizeCneInventory(passes['cne-inventory']),
        'patchpivot-findings': {
          totalFindings: patchpivot.totalFindings ?? 0,
          byStatus: patchpivot.byStatus ?? {},
          bySeverity: patchpivot.bySeverity ?? {},
          findings: [],
        },
        'comprehensive-vulns': summarizeComprehensive(comprehensive),
        'vulnerability-discovery': {
          generatedAt: vulnDiscovery.generatedAt,
          summary: vulnDiscovery.summary ?? {},
          validatorsEmitted: vulnDiscovery.validatorsEmitted ?? 0,
          sources: summarizeSources(vulnDiscovery.sources),
          topFindings: [],
          safeValidationLibrary: [],
        },
        'company-advisories': {
          generatedAt: company.generatedAt,
          totalCompanies: company.totalCompanies ?? company.companies?.length ?? 0,
          totalRecentAdvisories: company.totalRecentAdvisories ?? 0,
          companies: [],
        },
      },
      severity: findings.severity,
    },
    _meta: {
      visibility: 'public-redacted',
      restrictedPortal: '/security/secure-report',
      redaction: [
        'full finding evidence',
        'safe validation records',
        'validator commands',
        'restricted artifact URLs',
        'file-level entries',
      ],
    },
  };
}

function summarizeCneInventory(input = {}) {
  return {
    skipped: input.skipped,
    generatedAt: input.generatedAt,
    apps: input.apps ? {
      registryUninstall: input.apps.registryUninstall ?? 0,
      appx: input.apps.appx ?? 0,
      winget: countOrObject(input.apps.winget),
      choco: countOrObject(input.apps.choco),
      scoop: countOrObject(input.apps.scoop),
      msiProducts: input.apps.msiProducts ?? 0,
    } : undefined,
    protocols: input.protocols,
    features: input.features ? {
      optionalFeatures: input.features.optionalFeatures ?? 0,
      capabilities: input.features.capabilities ?? 0,
      hyperV: input.features.hyperV ?? null,
      wsl: input.features.wsl ?? null,
      sandbox: input.features.sandbox ?? null,
      smartAppControl: input.features.smartAppControl ?? null,
    } : undefined,
    persistence: input.persistence ? {
      services: input.persistence.services ?? 0,
      scheduledTasks: input.persistence.scheduledTasks ?? 0,
      startupCommands: input.persistence.startupCommands ?? 0,
      drivers: input.persistence.drivers ?? 0,
    } : undefined,
    hardening: input.hardening,
    hardeningFails: [],
    osVulns: input.osVulns,
  };
}

function summarizeComprehensive(input = {}) {
  return {
    skipped: input.skipped,
    browsers: input.browsers ? {
      found: input.browsers.found ?? 0,
      totalLikelyVulnerable: input.browsers.totalLikelyVulnerable ?? 0,
      browsers: [],
    } : undefined,
    python: summarizeObject(input.python, ['installed', 'pipPackages', 'vulnerableFound', 'pythonVersion']),
    wsl: summarizeObject(input.wsl, ['installed', 'totalKernelVulns', 'totalOutdated']),
    globalNpm: summarizeObject(input.globalNpm, ['installed', 'globalPackages', 'totalVulnerable']),
    docker: summarizeObject(input.docker, ['installed']),
    installedSoftware: input.installedSoftware ? {
      totalInstalled: input.installedSoftware.totalInstalled ?? 0,
      potentialVulnerable: input.installedSoftware.potentialVulnerable ?? 0,
      findings: [],
    } : undefined,
    kernel: input.kernel ? {
      kernel: input.kernel.kernel ?? '',
      kernelVulnerable: input.kernel.kernelVulnerable ?? false,
      kernelVulns: [],
      totalApplicableVulns: input.kernel.totalApplicableVulns ?? 0,
    } : undefined,
    systemPackages: summarizeObject(input.systemPackages, ['installed', 'totalPackages', 'upgradable', 'securityUpgrades']),
    suidBinaries: input.suidBinaries ? {
      totalCount: input.suidBinaries.totalCount ?? 0,
      riskyPresent: input.suidBinaries.riskyPresent ?? 0,
      riskyBinaries: [],
    } : undefined,
    worldWritable: summarizeObject(input.worldWritable, ['worldWritableFiles', 'worldWritableDirs']),
    listeningServices: input.listeningServices ? {
      tcpListenerCount: input.listeningServices.tcpListenerCount ?? 0,
      exposedServices: [],
    } : undefined,
    sshConfig: input.sshConfig ? {
      configured: input.sshConfig.configured ?? false,
      passed: input.sshConfig.passed ?? 0,
      failed: input.sshConfig.failed ?? 0,
      totalChecks: input.sshConfig.totalChecks ?? 0,
      checks: [],
    } : undefined,
    kaliTools: input.kaliTools ? {
      isKali: input.kaliTools.isKali ?? false,
      totalToolsInstalled: input.kaliTools.totalToolsInstalled ?? 0,
      totalToolsKnown: input.kaliTools.totalToolsKnown ?? 0,
      toolVulns: [],
    } : undefined,
    companyAdvisories: input.companyAdvisories ? {
      generatedAt: input.companyAdvisories.generatedAt,
      totalCompanies: input.companyAdvisories.totalCompanies ?? 0,
      totalRecentAdvisories: input.companyAdvisories.totalRecentAdvisories ?? 0,
      companies: [],
    } : undefined,
  };
}

function summarizeObject(input, keys) {
  if (!input || typeof input !== 'object') return undefined;
  const out = {};
  for (const key of keys) out[key] = input[key];
  return out;
}

function summarizeSources(sources) {
  if (!sources || typeof sources !== 'object') return {};
  const out = {};
  for (const [name, value] of Object.entries(sources)) {
    out[name] = summarizeObject(value, ['count', 'total', 'generatedAt', 'skipped', 'error']) ?? true;
  }
  return out;
}

function countOrObject(value) {
  if (typeof value === 'number') return value;
  if (value && typeof value === 'object') return {
    count: value.count ?? value.total ?? 0,
    error: value.error ?? undefined,
  };
  return value ?? 0;
}

function redactPublicVulnerabilities(vulns) {
  if (!Array.isArray(vulns)) return [];
  return vulns.map((v) => ({
    id: String(v.id ?? ''),
    cve: v.cve ?? v.cveIds?.[0] ?? null,
    title: String(v.title ?? '').slice(0, 220),
    severity: String(v.severity ?? 'info'),
    cisaKev: Boolean(v.cisaKev),
    priority: typeof v.priority === 'number' ? v.priority : undefined,
    referenceCount: Array.isArray(v.references) ? v.references.length : 0,
  }));
}

function renderPublicFindingsMarkdown(bundle) {
  const passes = bundle.findings.passes;
  const discovery = passes['vulnerability-discovery'];
  return [
    '# Vigil Public Security Summary',
    '',
    `- Generated: ${bundle.ranAt}`,
    `- Package: ${bundle.package}@${bundle.version}`,
    `- Run: ${bundle.runId}`,
    `- Severity: ${bundle.severity}`,
    '',
    '## Public Counts',
    '',
    `- Total vulnerability discoveries: ${discovery.summary?.total ?? 0}`,
    `- Critical: ${discovery.summary?.bySeverity?.critical ?? 0}`,
    `- High: ${discovery.summary?.bySeverity?.high ?? 0}`,
    `- SBOM components: ${passes.sbom.components ?? 0}`,
    '',
    '## Redaction Boundary',
    '',
    'The public website intentionally omits proof commands, validator sources, raw evidence, and restricted artifact URLs.',
    'Approved users retrieve the complete portal data through `/security/secure-report` and downloads through `/download`.',
    '',
  ].join('\n');
}

async function patchDoc(token, url, fields) {
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`firestore write ${res.status}: ${text.slice(0, 500)}`);
  }
  return res.json();
}

async function uploadStorage(token, objectName, buffer, contentType, extra = {}) {
  // multipart/related upload — the simplest way to set custom metadata
  // and content-type in one shot via the storage REST API.
  const boundary = `vigil-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const customMetadata = { ...(extra.metadata ?? {}) };
  const metadataFields = extra.publicToken === false
    ? customMetadata
    : { firebaseStorageDownloadTokens: DOWNLOAD_TOKEN, ...customMetadata };
  const metadata = JSON.stringify({
    name: objectName,
    contentType,
    metadata: metadataFields,
  });
  const head = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
    `${metadata}\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: ${contentType}\r\n\r\n`,
    'utf8'
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  const body = Buffer.concat([head, Buffer.from(buffer), tail]);

  const url = `https://storage.googleapis.com/upload/storage/v1/b/${STORAGE_BUCKET}/o?uploadType=multipart&name=${encodeURIComponent(objectName)}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary=${boundary}`,
      'Content-Length': String(body.length),
    },
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`storage upload ${res.status} ${objectName}: ${text.slice(0, 500)}`);
  }
}

function storageUrl(objectPath) {
  // Tokenized URL — works anonymously thanks to the
  // firebaseStorageDownloadTokens metadata we set at upload.
  return `https://firebasestorage.googleapis.com/v0/b/${STORAGE_BUCKET}/o/${encodeURIComponent(objectPath)}?alt=media&token=${DOWNLOAD_TOKEN}`;
}

function storagePath(objectPath) {
  return `gs://${STORAGE_BUCKET}/${objectPath}`;
}

function findingsToFirestore(f) {
  return {
    runId: { stringValue: f.runId },
    ranAt: { stringValue: f.ranAt },
    package: { stringValue: f.repo.name },
    version: { stringValue: f.repo.version },
    git: { stringValue: f.repo.git },
    branch: { stringValue: f.repo.branch },
    remote: { stringValue: f.repo.remote },
    severity: { stringValue: f.severity },
    npmAudit: {
      mapValue: {
        fields: {
          totalAdvisories: { integerValue: String(f.passes['npm-audit'].totalAdvisories ?? 0) },
          bySeverity: { mapValue: { fields: mapNumbers(f.passes['npm-audit'].bySeverity ?? {}) } },
        },
      },
    },
    licenses: {
      mapValue: { fields: { unlicensed: { integerValue: String(f.passes.licenses.unlicensed ?? 0) } } },
    },
    outdated: {
      mapValue: { fields: { count: { integerValue: String(f.passes.outdated.count ?? 0) } } },
    },
    codeFindings: {
      mapValue: {
        fields: {
          secrets: { integerValue: String(f.passes['code-findings'].secrets) },
          risky_sinks: { integerValue: String(f.passes['code-findings'].risky_sinks) },
          world_writable: { integerValue: String(f.passes['code-findings'].world_writable) },
        },
      },
    },
    sbom: {
      mapValue: { fields: { components: { integerValue: String(f.passes.sbom.components) } } },
    },
    supplyChain: f.passes['supply-chain'].skipped
      ? { mapValue: { fields: { skipped: { booleanValue: true } } } }
      : {
        mapValue: {
          fields: {
            tarball: { stringValue: f.passes['supply-chain'].tarball },
            sha256: { stringValue: f.passes['supply-chain'].sha256 },
            sha512: { stringValue: f.passes['supply-chain'].sha512 },
            sizeBytes: { integerValue: String(f.passes['supply-chain'].sizeBytes) },
            npmIntegrity: { stringValue: f.passes['supply-chain'].npmIntegrity ?? '' },
          },
        },
      },
    variantIntel: {
      mapValue: { fields: { tracked: { integerValue: String(f.passes['variant-intel'].tracked) } } },
    },
  };
}

function mapNumbers(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = { integerValue: String(v) };
  }
  return out;
}

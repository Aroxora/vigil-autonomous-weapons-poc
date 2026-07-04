// apps.mjs — Pack A: installed-app inventory.
// Sources: registry uninstall (HKLM 32+64 + HKCU), Appx/MSIX,
// winget, choco, scoop, Get-Package (Programs/msi/msu providers).

import { runPs, readPs } from './_ps.mjs';

const SCRIPTS = {
  registryUninstall: 'apps-registry.ps1',
  appx:              'apps-appx.ps1',
  winget:            'apps-winget.ps1',
  choco:             'apps-choco.ps1',
  scoop:             'apps-scoop.ps1',
  getPackage:        'apps-getpackage.ps1',
};

const TIMEOUTS = {
  registryUninstall: 60_000,
  appx:              45_000,
  winget:            60_000,
  choco:             15_000,
  scoop:             15_000,
  getPackage:        60_000,
};

export async function runAppsPack() {
  const generatedAt = new Date().toISOString();
  const t0 = Date.now();
  const sections = {};
  for (const [key, file] of Object.entries(SCRIPTS)) {
    sections[key] = wrap(runPs(readPs(file), { depth: 3, timeoutMs: TIMEOUTS[key] }));
  }

  const allApps = [];
  for (const s of Object.values(sections)) {
    if (Array.isArray(s.value)) allApps.push(...s.value);
  }

  return {
    pack: 'apps',
    generatedAt,
    durationMs: Date.now() - t0,
    sections,
    tally: {
      totalRows: allApps.length,
      bySource: tallyBy(allApps, 'source'),
      topPublishers: topNBy(allApps, 'publisher', 15),
    },
  };
}

function wrap(r) {
  if (r?.ok === false) return { ok: false, error: r.error, count: 0, value: [] };
  const v = r?.value ?? r;
  const arr = Array.isArray(v) ? v : (v == null ? [] : [v]);
  return { ok: true, count: arr.length, value: arr };
}

function tallyBy(arr, key) {
  const out = {};
  for (const it of arr) {
    const k = it?.[key] ?? '(none)';
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function topNBy(arr, key, n) {
  const tally = tallyBy(arr, key);
  return Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, n)
    .map(([name, count]) => ({ name, count }));
}

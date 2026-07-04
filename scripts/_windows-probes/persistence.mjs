// persistence.mjs — Pack D: full Windows persistence surface.
// services, scheduled tasks, startup commands, Run/RunOnce, startup
// folders, drivers (with Authenticode signature), browser extensions,
// WMI permanent event subscriptions.

import { runPs, readPs } from './_ps.mjs';

const SCRIPTS = {
  services:        'persist-services.ps1',
  scheduledTasks:  'persist-scheduled-tasks.ps1',
  startupCommands: 'persist-startup-commands.ps1',
  runKeys:         'persist-run-keys.ps1',
  startupFolders:  'persist-startup-folders.ps1',
  drivers:         'persist-drivers.ps1',
  browserExtensions:'persist-browser-extensions.ps1',
  wmiSubscriptions:'persist-wmi-subscriptions.ps1',
};

const TIMEOUTS = {
  services: 30_000, scheduledTasks: 60_000, startupCommands: 20_000,
  runKeys: 15_000, startupFolders: 10_000, drivers: 120_000,
  browserExtensions: 45_000, wmiSubscriptions: 20_000,
};

export async function runPersistencePack() {
  const generatedAt = new Date().toISOString();
  const t0 = Date.now();
  const sections = {};
  for (const [k, file] of Object.entries(SCRIPTS)) {
    sections[k] = wrap(runPs(readPs(file), { depth: 5, timeoutMs: TIMEOUTS[k] }));
  }
  return {
    pack: 'persistence',
    generatedAt,
    durationMs: Date.now() - t0,
    sections,
    risks: deriveRisks(sections),
    tally: {
      services: sections.services.count,
      scheduledTasks: sections.scheduledTasks.count,
      startupCommands: sections.startupCommands.count,
      runKeys: sections.runKeys.count,
      startupFolders: sections.startupFolders.count,
      drivers: sections.drivers.count,
      browserExtensions: sections.browserExtensions.count,
      wmiFilters: arrCount(sections.wmiSubscriptions.value?.filters),
      wmiCommandLineConsumers: arrCount(sections.wmiSubscriptions.value?.commandLineConsumers),
    },
  };
}

function wrap(r) {
  if (r?.ok === false) return { ok: false, error: r.error, count: 0, value: [] };
  const v = r?.value ?? r;
  const arr = Array.isArray(v) ? v : (v == null ? [] : [v]);
  return { ok: true, count: arr.length, value: arr };
}

function arrCount(v) {
  if (Array.isArray(v)) return v.length;
  if (v == null) return 0;
  return 1;
}

const KNOWN_OK_DRIVER_PUBLISHERS = [
  'Microsoft Windows', 'Microsoft Corporation', 'Microsoft Windows Hardware Compatibility Publisher',
  'Intel Corporation', 'NVIDIA Corporation', 'Advanced Micro Devices', 'Realtek Semiconductor Corp.',
  'Qualcomm Technologies, Inc.', 'Broadcom Corporation', 'Synaptics Incorporated',
  'Microsoft Code Signing Verification PCA', 'Apple Inc.', 'Logitech', 'ASUSTeK COMPUTER INC.',
];

function deriveRisks(s) {
  const out = [];

  // Unsigned-or-untrusted drivers — Stuxnet-class signal per the threat-cases page.
  const drivers = s.drivers?.value ?? [];
  for (const d of drivers) {
    const status = d.signature?.status;
    if (status && status !== 'Valid' && status !== 'UnknownError') {
      out.push({ id: 'driver-bad-signature', severity: 'high', why: `Driver ${d.name} signature status=${status}: ${d.pathName}` });
    } else if (status === 'Valid' && d.signature?.signerCert_Subject) {
      const subj = d.signature.signerCert_Subject;
      const known = KNOWN_OK_DRIVER_PUBLISHERS.some(p => subj.includes(p));
      if (!known) {
        out.push({ id: 'driver-unusual-publisher', severity: 'low', why: `Driver ${d.name} signed by non-major publisher: ${subj.slice(0, 120)}` });
      }
    }
  }

  // PsExec-style scheduled tasks that exec from non-Windows dirs
  for (const t of s.scheduledTasks?.value ?? []) {
    const exec = (t.execute ?? '').toLowerCase();
    if (exec && !exec.includes('windows\\') && !exec.includes('program files') && !exec.match(/^[a-z]:\\(?:windows|program)/)) {
      if (exec.match(/\.(exe|ps1|bat|cmd|vbs|wsf|js)/)) {
        out.push({ id: 'scheduled-task-non-system-dir', severity: 'low', why: `Task ${t.taskPath}${t.taskName} execs outside system dirs: ${t.execute}` });
      }
    }
  }

  // Run-key entries that include cmd /c download patterns
  for (const r of s.runKeys?.value ?? []) {
    const cmd = (r.command ?? '').toLowerCase();
    if (cmd.match(/(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)/)) {
      out.push({ id: 'run-key-lolbin', severity: 'moderate', why: `Run key ${r.name} uses LOLBin
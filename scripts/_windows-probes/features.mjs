// features.mjs — Pack C: Windows 11 Pro features & security posture beyond network surface.

import { runPs, readPs } from './_ps.mjs';

const SCRIPTS = {
  edition:           'feat-edition.ps1',
  optionalFeatures:  'feat-optional.ps1',
  capabilities:      'feat-capabilities.ps1',
  deviceGuard:       'feat-deviceguard.ps1',
  defenderAsr:       'feat-defender-asr.ps1',
  exploitProtection: 'feat-exploit-protection.ps1',
  wdacSac:           'feat-wdac-sac.ps1',
  uac:               'feat-uac.ps1',
  windowsUpdate:     'feat-windows-update.ps1',
  helloSmartscreen:  'feat-hello-smartscreen.ps1',
};

const TIMEOUTS = {
  edition: 20_000, optionalFeatures: 60_000, capabilities: 60_000,
  deviceGuard: 15_000, defenderAsr: 15_000, exploitProtection: 15_000,
  wdacSac: 15_000, uac: 10_000, windowsUpdate: 20_000,
  helloSmartscreen: 10_000,
};

export async function runFeaturesPack() {
  const generatedAt = new Date().toISOString();
  const t0 = Date.now();
  const sections = {};
  for (const [k, file] of Object.entries(SCRIPTS)) {
    sections[k] = unwrap(runPs(readPs(file), { depth: 5, timeoutMs: TIMEOUTS[k] }));
  }
  return {
    pack: 'features',
    generatedAt,
    durationMs: Date.now() - t0,
    sections,
    risks: deriveRisks(sections),
  };
}

function unwrap(r) {
  if (r?.ok === false) return { ok: false, error: r.error };
  return { ok: true, value: r?.value ?? null };
}

function deriveRisks(s) {
  const out = [];
  const dg = s.deviceGuard?.value;
  if (dg && Array.isArray(dg.SecurityServicesRunning)) {
    const running = new Set(dg.SecurityServicesRunning);
    if (!running.has(1)) out.push({ id: 'cred-guard-not-running', severity: 'moderate', why: 'Credential Guard not running (SecurityServicesRunning lacks 1)' });
    if (!running.has(2)) out.push({ id: 'hvci-not-running', severity: 'moderate', why: 'HVCI / Memory Integrity not running (SecurityServicesRunning lacks 2)' });
  }
  const asr = s.defenderAsr?.value;
  if (asr && Array.isArray(asr.asrRules)) {
    const enabled = asr.asrRules.filter(r => r.action === 1 || r.action === 6).length;
    if (enabled === 0) {
      out.push({ id: 'asr-no-rules', severity: 'high', why: 'No Defender ASR rules in Block or Warn — Volt-Typhoon-class LOTL chains unmitigated' });
    } else if (enabled < 8) {
      out.push({ id: 'asr-thin-coverage', severity: 'moderate', why: `Only ${enabled} ASR rules in Block/Warn — Microsoft recommends all 16 enabled` });
    }
  }
  if (asr?.disableRealtimeMonitoring === true || asr?.disableRealtimeMonitoring === 1) {
    out.push({ id: 'defender-realtime-off', severity: 'high', why: 'Defender real-time monitoring disabled' });
  }
  if (asr?.enableControlledFolderAccess === 0) {
    out.push({ id: 'cfa-disabled', severity: 'low', why: 'Controlled Folder Access disabled — ransomware mitigation off' });
  }
  if (asr?.enableNetworkProtection === 0) {
    out.push({ id: 'network-protection-disabled', severity: 'low', why: 'SmartScreen Network Protection disabled' });
  }
  const uac = s.uac?.value;
  if (uac?.EnableLUA === 0) out.push({ id: 'uac-disabled', severity: 'high', why: 'UAC disabled (EnableLUA=0)' });
  if (uac?.ConsentPromptBehaviorAdmin != null && uac.ConsentPromptBehaviorAdmin < 2) {
    out.push({ id: 'uac-weak-admin-prompt', severity: 'moderate', why: `UAC admin consent behavior=${uac.ConsentPromptBehaviorAdmin} (2+ recommended)` });
  }
  const sac = s.wdacSac?.value?.smartAppControl_state;
  if (sac !== undefined && sac !== 1 && sac !== 2) {
    out.push({ id: 'smart-app-control-off', severity: 'low', why: `Smart App Control state=${sac} (1=on, 2=eval)` });
  }
  const ss = s.helloSmartscreen?.value;
  if (ss?.explorerSmartScreen && ss.explorerSmartScreen !== 'RequireAdmin' && ss.explorerSmartScreen !== 'On') {
    out.push({ id: 'explorer-smartscreen-off', severity: 'moderate', why: `Explorer SmartScreen=${ss.explorerSmartScreen}` });
  }
  return out;
}

// protocols.mjs — Pack B: protocol surface enablement.

import { runPs, readPs } from './_ps.mjs';

const SCRIPTS = {
  smb:        'proto-smb.ps1',
  tls:        'proto-tls.ps1',
  ntlm:       'proto-ntlm.ps1',
  kerberos:   'proto-kerberos.ps1',
  llmnrMdns:  'proto-llmnr.ps1',
  netbios:    'proto-netbios.ps1',
  wpad:       'proto-wpad.ps1',
  winrm:      'proto-winrm.ps1',
  rdp:        'proto-rdp.ps1',
  ipv6:       'proto-ipv6.ps1',
  ipsec:      'proto-ipsec.ps1',
  doh:        'proto-doh.ps1',
  wifi:       'proto-wifi.ps1',
  powershell: 'proto-powershell.ps1',
};

const TIMEOUTS = {
  smb: 20_000, tls: 15_000, ntlm: 10_000, kerberos: 10_000,
  llmnrMdns: 10_000, netbios: 15_000, wpad: 15_000, winrm: 20_000,
  rdp: 10_000, ipv6: 15_000, ipsec: 15_000, doh: 15_000,
  wifi: 15_000, powershell: 10_000,
};

export async function runProtocolsPack() {
  const generatedAt = new Date().toISOString();
  const t0 = Date.now();
  const sections = {};
  for (const [k, file] of Object.entries(SCRIPTS)) {
    sections[k] = unwrap(runPs(readPs(file), { depth: 4, timeoutMs: TIMEOUTS[k] }));
  }
  return {
    pack: 'protocols',
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
  const smb = s.smb?.value;
  if (smb?.server?.EnableSMB1Protocol === true || smb?.smb1Feature?.State === 'Enabled') {
    out.push({ id: 'smb1-enabled', severity: 'high', why: 'SMB1 enabled — Eternalblue family + LM auth' });
  }
  if (smb?.server?.RequireSecuritySignature === false) {
    out.push({ id: 'smb-signing-not-required', severity: 'moderate', why: 'SMB server does not require signing' });
  }
  if (smb?.client?.EnableInsecureGuestLogons === true) {
    out.push({ id: 'smb-insecure-guest', severity: 'moderate', why: 'SMB client allows insecure guest logons' });
  }
  const tls = s.tls?.value?.schannel;
  for (const v of ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1']) {
    const cli = tls?.[v]?.Client;
    const srv = tls?.[v]?.Server;
    const enabled = (x) => x && (x.Enabled === 1 || x.Enabled === true || x.Enabled === undefined);
    if (enabled(cli) || enabled(srv)) {
      out.push({ id: `legacy-${v.toLowerCase().replace(/[ .]/g, '')}-enabled`, severity: 'high', why: `${v} should be disabled` });
    }
  }
  const lm = s.ntlm?.value?.LmCompatibilityLevel;
  if (typeof lm === 'number' && lm < 5) {
    out.push({ id: 'ntlm-weak', severity: 'moderate', why: `LmCompatibilityLevel=${lm} (NTLMv2-only is 5)` });
  }
  if (s.llmnrMdns?.value?.LLMNR_EnableMulticast === 1) {
    out.push({ id: 'llmnr-enabled', severity: 'moderate', why: 'LLMNR enabled — Responder/NTLM-relay vector' });
  }
  const wpad = s.wpad?.value?.service;
  if (wpad?.Status === 'Running' && wpad?.StartType === 'Automatic') {
    out.push({ id: 'wpad-running', severity: 'low', why: 'WPAD service running — adjacent-network MITM exposure' });
  }
  const rdp = s.rdp?.value;
  if (rdp?.fDenyTSConnections === 0) {
    if (rdp?.UserAuthentication === 0) {
      out.push({ id: 'rdp-no-nla', severity: 'high', why: 'RDP enabled without NLA' });
    }
    if (rdp?.MinEncryptionLevel != null && rdp.MinEncryptionLevel < 3) {
      out.push({ id: 'rdp-weak-encryption', severity: 'moderate', why: `RDP MinEncryptionLevel=${rdp.MinEncryptionLevel} (3=High)` });
    }
  }
  const ps = s.powershell?.value;
  if (ps && ps.scriptBlockLogging !== 1) {
    out.push({ id: 'ps-no-script-block-logging', severity: 'moderate', why: 'PowerShell script-block logging not enabled — Volt-Typhoon-style LOTL detection gap' });
  }
  if (ps && ps.transcription !== 1) {
    out.push({ id: 'ps-no-transcription', severity: 'low', why: 'PowerShell transcription not enabled' });
  }
  return out;
}

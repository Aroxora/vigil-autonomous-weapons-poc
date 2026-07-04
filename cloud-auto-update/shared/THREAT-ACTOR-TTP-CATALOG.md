# Threat Actor TTP Catalog — Full Technical Detail
## 23 Nation-State + E-Crime Groups Tracked by Vigil

---

## Russia (6 Groups)

### Forest Blizzard (APT28 / Fancy Bear)
**Sponsor:** GRU Unit 26165 (Russian military intelligence)  
**First Seen:** 2004  
**Status:** ELEVATED  


**TTPs (MITRE ATT&CK):**
- T1566.001 — Spear-phishing Attachment (weaponized Office docs with CVE-2017-11882)
- T1059.001 — PowerShell execution (encoded commands, AMSI bypass via reflection)
- T1055 — Process Injection (lsass.exe, explorer.exe via CreateRemoteThread)
- T1552.001 — OS Credential Dumping (Mimikatz, ProcDump, comsvcs.dll MiniDump)
- T1567 — Exfiltration Over Web Service (HTTPS to compromised WordPress sites)
- T1136 — Create Account (domain admin persistence)
- T1082 — System Information Discovery (wmic, net, systeminfo)
- T1098 — Account Manipulation (OAuth consent grant abuse for persistent Mail access)

**Known Tooling:**
- **X-Agent/X-Tunnel:** C++ backdoor; C2 over HTTPS with custom XOR + AES encryption
- **Zebrocy:** Multi-language malware (Delphi, Go, C#, Python, VB.NET variants)
- **Drovorub:** Linux kernel rootkit (LKM); hides files, processes, network connections
- **CredoMap:** Credential theft; browser data + email store exfiltration
- **VPNFilter:** Router malware; destructive stage 3 kill command; mirai-based stage 1

**CVEs Exploited:** CVE-2017-11882, CVE-2023-23397, CVE-2022-30190 (Follina), CVE-2021-40444

---

### Midnight Blizzard (APT29 / Cozy Bear / Nobelium)
**Sponsor:** SVR (Russian foreign intelligence)  
**First Seen:** 2008  
**Status:** ELEVATED  

**TTPs:**
- T1190 — Exploit Public-Facing Application (Exchange, VPN appliances)
- T1114.002 — Email Collection (full Mail.Read OAuth grants)
- T1598 — Phishing for Information (Teams phishing with impersonated IT accounts)
- T1586 — Compromise Accounts (password spray with low-and-slow timing)
- T1505 — Server Software Component (web shells via ProxyShell/ProxyLogon)
- T1027 — Obfuscated Files (custom packers, VMProtect, Themida)
- T1053 — Scheduled Task (persistence via schtasks with dummy names)
- T1484 — Domain Policy Modification (federation trust, token signing certs)

**Known Tooling:**
- **SUNBURST:** SolarWinds supply chain backdoor; HTTP to avsvmcloud[.]com C2; DGA fallback
- **TEARDROP:** Memory-only dropper; Cobalt Strike Beacon loader; no disk persistence
- **Raindrop:** Second-stage loader for Cobalt Strike; DLL side-loading via 7z.exe
- **GoldMax/GoldFinder/Sibot:** Linux malware; HTTP tracer scripts for Azure/AD probing
- **MagicWeb:** ADFS backdoor; malicious DLL injected into ADFS managed pipeline

**CVEs Exploited:** CVE-2021-26855 (ProxyLogon), CVE-2021-34473 (ProxyShell), CVE-2023-23397

---

### Seashell Blizzard (Sandworm / IRIDIUM)
**Sponsor:** GRU Unit 74455  
**First Seen:** 2007  
**Status:** WATCH  

**TTPs:**
- T0831 — Manipulation of Control (ICS protocol manipulation via IEC 61850/IEC 60870-5-104)
- T1485 — Data Destruction (NotPetya — MBR overwrite via EternalBlue lateral + scheduled task)
- T1569 — System Services (PsExec, WMI for lateral movement)
- T1043 — Commonly Used Port (SSH tunneling, SOCKS proxy via compromised routers)
- T1543 — Create or Modify System Process (kernel driver manipulation)
- T1021 — Remote Services (RDP via stolen credentials, VNC)

**Known Tooling:**
- **Industroyer2:** ICS-specific modular malware; IEC-104 protocol abuse; injects malicious commands directly to RTUs
- **NotPetya:** Destructive ransomware; MFT encryption; Petya MBR overwrite; propagates via EternalBlue+EternalRomance
- **BlackEnergy:** Modular malware; custom KillDisk module for ICS destruction
- **Olympic Destroyer:** MBR wiper; false flag (planted North Korea artifacts via embedded Chinese+Korean strings)
- **Cyclops Blink:** Linux-based router botnet; WatchGuard firewall VPN exploitation; modular C2 protocol

**CVEs Exploited:** CVE-2017-0144 (EternalBlue), CVE-2019-0708 (BlueKeep), CVE-2022-23176 (WatchGuard)

---

### Aqua Blizzard (Gamaredon / Iron Tildon)
**Sponsor:** FSB (Russian security service)  
**First Seen:** 2013  
**Status:** TRACKED  

**TTPs:**
- T1059.001 — PowerShell (script obfuscation, AMSI bypass, download cradle)
- T1091 — Replication Through Removable Media (USB autorun.inf, LNK weaponization)
- T1003 — OS Credential Dumping (custom credential harvesters)
- T1027.002 — Software Packing (custom XOR/RC4 obfuscation)

**Known Tooling:** Pterodo/Pteranodon family; rapid (~2h) infrastructure rotation; self-extracting SFX payloads with nested VBS/PowerShell/PE layers

---

### Cadet Blizzard (APT44 / DEV-0586)
**Sponsor:** GRU  
**First Seen:** 2022  
**Status:** WATCH  

**TTPs:**
- T1485 — Data Destruction (WhisperGate — MBR overwrite + file corruption via EaseUS driver abuse)
- T1561 — Disk Wipe (RawDisk driver for direct sector writes)
- T1070 — Indicator Removal (time stomping, USN journal purge)
- T1059.001 — PowerShell (PowerShell Empire, Cobalt Strike)

**Known Tooling:** WhisperGate (MBR wiper + file corrupter), DEV-0586 custom PowerShell stagers, commodity ransomware pretexts

---

### Turla (Venomous Bear / Snake)
**Sponsor:** FSB  
**First Seen:** 2004  
**Status:** TRACKED  

**TTPs:**
- T1090 — Proxy (satellite-based C2 — hijacked downstream satellite links for anonymous upstream)
- T1203 — Exploitation for Client Execution (Flash, Java exploits via watering hole)
- T1505.003 — Web Shell (custom ASPX webshells, IIS module manipulation)
- T1574.002 — DLL Side-Loading (legitimate Kaspersky/Sophos DLLs hijacked)

**Known Tooling:** Snake rootkit (Windows+Linux), Kazuar (C# backdoor), ComRAT v4 (Gmail-based C2)

---

## China (6 Groups)

### Volt Typhoon (Bronze Starlight)
**Sponsor:** MSS/PLA  
**First Seen:** 2021  
**Status:** ELEVATED  

**TTPs:**
- T1190 — Edge device exploitation (FortiOS, Citrix Netscaler, F5 Big-IP)
- T1071.001 — Web Protocols (HTTPS tunneling via FRP/fast-reverse-proxy, Ngrok, Cloudflare Tunnel)
- T1083 — File/Directory Discovery (dir, tree, Get-ChildItem Recurse)
- T1059.003 — Windows Command Shell (cmd /q /c for EVERY command — maximum stealth)
- T1043 — HTTP traffic on port 443 mixed with legitimate traffic

**Key TTP — Living off the Land (LoL):**
- Exclusively uses built-in Windows tools (no custom malware dropped to disk)
- PowerShell/WMIC/cmd for EVERY operation
- FRP (Fast Reverse Proxy): open-source tool for C2 tunneling
- Network scanning via built-in netstat/netsh without triggering AV

---

### Brass Typhoon (APT41 / Winnti Group)
**Sponsor:** MSS (dual mission — state espionage + financial crime)  
**First Seen:** 2012  
**Status:** ELEVATED  

**TTPs:**
- T1195 — Supply Chain Compromise (trojanized game mods, IDE plugins, npm packages)
- T1574.002 — DLL Side-Loading (signed binaries: NVIDIA, Google, Adobe, Microsoft)
- T1553.004 — Install Root Certificate (custom code-signing certs)
- T1106 — Native API (direct NTDLL.DLL syscall invocations)

**Known Tooling:** Winnti backdoor, ShadowPad (node.js-based modular RAT), cross-platform C++ implant with C2 over HTTPS/TCP/UDP

---

### Silk Typhoon (Hafnium / HOLMIUM)
**Sponsor:** MSS  
**First Seen:** 2020  
**Status:** ELEVATED  

**TTPs:**
- T1190 — Exchange exploitation (ProxyLogon CVE-2021-26855, ProxyShell CVE-2021-34473)
- T1505.003 — Web Shell deployment (China Chopper, ASPXSpy, AntSword)
- T1068 — Exploitation for Privilege Escalation (CVE-2021-27065, CVE-2021-26857)

**CVEs Exploited:** CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-34473

---

### Granite Typhoon (APT10 / Stone Panda)
**Sponsor:** PLA  
**First Seen:** 2006  
**Status:** ELEVATED  

**TTPs:**
- T1195 — MSP/cloud provider supply chain compromise
- T1078 — Valid Accounts (stolen MSP credentials for lateral movement to customer tenants)
- T1027 — PE loading via reflective DLL injection
- T1485 — Data Destruction (CloudHopper — targeted data theft + cover-up deletion)

**Known Tooling:** Poison Ivy RAT, PlugX (modular backdoor), Gh0st RAT, RedLeaves (PlugX derivative for lateral movement)

---

## North Korea (4 Groups)

### Diamond Sleet (Lazarus Group / ZINC)
**Sponsor:** RGB (Reconnaissance General Bureau)  
**First Seen:** 2009  
**Status:** ELEVATED  

**TTPs:**
- T1195.002 — Compromise Software Supply Chain (3CX DesktopApp trojanization — CVE-2023-29059 with FFmpeg DLL sideload)
- T1566 — Social engineering (fake LinkedIn profiles, fake job offers with weaponized PDFs)
- T1647 — Deobfuscate/Decode (multi-stage shellcode: XOR → RC4 → custom cipher unpacking)
- T1583 — Acquire Infrastructure (rented European cloud servers for C2, blending into normal traffic)
- T1525 — Implant Internal Image (macOS malware: OSX.AppleJeus; Linux malware: Operation Dream Job)

**CVEs Exploited:** CVE-2023-29059 (3CX), CVE-2021-44228 (Log4Shell via VMware Horizon), CVE-2022-47966 (ManageEngine)

---

## Iran (4 Groups)

### Mint Sandstorm (APT35 / Charming Kitten)
**Sponsor:** IRGC  
**First Seen:** 2013  
**Status:** ELEVATED  

**TTPs:**
- T1598 — WhatsApp/Telegram/Instagram social engineering (impersonating journalists, activists, researchers)
- T1111 — Multi-Factor Authentication Interception (MFA fatigue/prompt bombing + SIM swap)
- T1505.003 — Web Shell (custom PHP/ASP shells for Exchange exploitation)
- T1059.001 — PowerShell (HYPERSCRAPE — PowerShell-based email exfiltration from Gmail/Yahoo)

**Known Tooling:** POWBAT (PowerShell backdoor), HYPERSCRAPE (email scraper), DarkHydrus (Google Drive C2)

---

## E-Crime (3 Groups)

### Scattered Spider (Octo Tempest / 0ktapus)
**Sponsor:** Criminal gang (US/UK based, English-speaking, Gen Z)  
**First Seen:** 2022  
**Status:** ELEVATED  

**TTPs:**
- T1598 — Social engineering via telecom help desk (SIM swap + MFA reset)
- T1621 — Multi-Factor Authentication Request Generation (MFA fatigue attack: 100+ push notifications until target approves)
- T1078.004 — Cloud Accounts (Okta Super Admin role assignment via compromised help desk)
- T1059.001 — PowerShell (invoke-command + remote PS sessions)
- T1486 — Data Encrypted for Impact (ALPHV/BlackCat RaaS deployment — Rust-based ransomware)

**Known Tooling:** Stonemouth/Knotweed (custom C# RAT), Teams phishing, Twilio/Cloudflare/MGM/Caesars social engineering

---

## Cross-Group TTP Index

| TTP | Groups | MITRE ATT&CK ID |
|-----|--------|----------------|
| Spear-phishing attachment | Forest Blizzard, Diamond Sleet, Mint Sandstorm | T1566.001 |
| PowerShell execution | ALL Russia/China/DPRK/Iran groups | T1059.001 |
| Supply chain compromise | Midnight Blizzard, Brass Typhoon, Diamond Sleet | T1195 |
| Credential dumping | Forest Blizzard, Aqua Blizzard, Granite Typhoon | T1003 |
| Web shell deployment | Midnight Blizzard, Silk Typhoon, Mint Sandstorm | T1505.003 |
| Data destruction/wiper | Seashell Blizzard, Cadet Blizzard, Granite Typhoon | T1485 |
| C2 over HTTPS | ALL groups | T1071.001 |
| DLL side-loading | Brass Typhoon, Turla | T1574.002 |
| Social engineering MFA | Scattered Spider, Mint Sandstorm | T1598 / T1621 |
| Living off the land | Volt Typhoon (exclusively) | T1059.001/T1083 |
| Router/edge device C2 | Seashell Blizzard, Volt Typhoon | T1190 |
| Valid accounts lateral | Granite Typhoon, Midnight Blizzard | T1078 |

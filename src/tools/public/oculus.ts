/**
 * Oculus — Public API
 * OSINT reconnaissance: DNS, crt.sh CT logs, WHOIS, Shodan, nmap.
 * Proxies to src/core/oculus.ts (541 lines).
 * import { oculus } from 'anvilwing/tools';
 */
export { runOculus as oculus } from '../../core/oculus.js';
export type { OculusConfig as OculusOptions, OculusResult, DnsRecords, WhoisData, ServiceInfo, TechnologyInfo, CloudAsset } from '../../core/oculus.js';

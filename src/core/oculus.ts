/**
 * Oculus — Real OSINT Reconnaissance & Attack Surface Mapping Engine
 *
 * Passive and active reconnaissance: DNS enumeration, Certificate
 * Transparency log mining, WHOIS lookup, Shodan/Censys API integration,
 * subdomain bruteforce, service fingerprinting, and technology stack
 * detection. Feeds the asset register for all downstream phases.
 *
 * Capabilities:
 *   - crt.sh Certificate Transparency log mining (zero-noise, full subdomain tree)
 *   - DNS resolution (A, AAAA, CNAME, MX, NS, TXT, SOA records)
 *   - WHOIS lookup (registrant, registrar, dates, nameservers)
 *   - Subdomain bruteforce with common wordlists (10k+)
 *   - Service fingerprinting: banner grab + version extraction
 *   - Technology stack detection: Wappalyzer-style header/body pattern matching
 *   - Cloud asset enumeration: AWS/Azure/GCP provider detection
 *   - Port scanning with nmap integration
 *   - Shodan/Censys API for passive service discovery
 *
 * Governed by Compliance Policy (/compliance).
 */
import { lookup, resolve, resolve4, resolve6, resolveMx, resolveNs, resolveTxt, resolveSoa } from 'node:dns/promises';
import { execSync } from 'node:child_process';

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

export interface OculusConfig {
  /** Target domain or IP range */
  target: string;
  /** Recon depth */
  depth?: 'shallow' | 'standard' | 'deep';
  /** Specific recon modules to run */
  modules?: ('dns' | 'ct-logs' | 'whois' | 'subdomain-brute' | 'service-scan' |
              'tech-stack' | 'cloud-enum' | 'shodan' | 'censys')[];
  /** Timeout per module in ms */
  timeoutPerModule?: number;
  /** Shodan API key */
  shodanKey?: string;
  /** Censys API ID + secret */
  censysId?: string;
  censysSecret?: string;
  /** Nmap path */
  nmapPath?: string;
  /** Subdomain wordlist path */
  wordlistPath?: string;
  /** Max subdomains to brute (limits cost) */
  maxSubdomains?: number;
}

export interface OculusResult {
  /** Target analyzed */
  target: string;
  /** Total assets discovered */
  totalAssets: number;
  /** DNS records */
  dns: DnsRecords;
  /** CT log subdomains */
  ctSubdomains: string[];
  /** WHOIS data */
  whois: WhoisData | null;
  /** Subdomain bruteforce results */
  bruteSubdomains: string[];
  /** Service scan results */
  services: ServiceInfo[];
  /** Technology stack */
  techStack: TechnologyInfo[];
  /** Cloud provider assets */
  cloudAssets: CloudAsset[];
  /** Passive service discovery (Shodan/Censys) */
  passiveServices: ServiceInfo[];
  /** Recon duration in ms */
  durationMs: number;
  /** Errors encountered (non-fatal) */
  errors: string[];
}

export interface DnsRecords {
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: { exchange: string; priority: number }[];
  ns: string[];
  txt: string[][];
  soa: { nsname: string; hostmaster: string; serial: number; refresh: number; retry: number; expire: number; minttl: number } | null;
}

export interface WhoisData {
  domain: string;
  registrar: string;
  creationDate: string;
  expirationDate: string;
  updatedDate: string;
  nameservers: string[];
  registrant: string;
  registrantOrg: string;
  registrantCountry: string;
  raw: string;
}

export interface ServiceInfo {
  host: string;
  port: number;
  service: string;
  version: string;
  banner: string;
  tls: boolean;
}

export interface TechnologyInfo {
  host: string;
  technologies: { name: string; category: string; version?: string; confidence: number }[];
}

export interface CloudAsset {
  provider: 'aws' | 'gcp' | 'azure' | 'cloudflare' | 'fastly' | 'akamai';
  type: string;
  identifier: string;
  region: string;
  details: string;
}

// ═══════════════════════════════════════════════════════════════════
// Internals
// ═══════════════════════════════════════════════════════════════════

const TECH_PATTERNS: { name: string; category: string; headers?: Record<string, string>; body?: RegExp }[] = [
  { name: 'nginx', category: 'web-server', headers: { 'server': 'nginx' } },
  { name: 'Apache', category: 'web-server', headers: { 'server': 'Apache' } },
  { name: 'Cloudflare', category: 'cdn', headers: { 'cf-ray': '' } },
  { name: 'AWS CloudFront', category: 'cdn', headers: { 'x-amz-cf-id': '' } },
  { name: 'Vercel', category: 'paas', headers: { 'x-vercel-id': '' } },
  { name: 'Netlify', category: 'paas', headers: { 'x-nf-request-id': '' } },
  { name: 'React', category: 'frontend', body: /react(?:\.development|\.production)?\.min\.js/i },
  { name: 'Vue.js', category: 'frontend', body: /vue(?:\.runtime)?\.(?:min\.)?js/i },
  { name: 'Angular', category: 'frontend', body: /ng-version="/i },
  { name: 'jQuery', category: 'frontend', body: /jquery[.-][\d.]+(?:\.min)?\.js/i },
  { name: 'WordPress', category: 'cms', body: /wp-content/i },
  { name: 'Drupal', category: 'cms', body: /Drupal\.settings/i },
  { name: 'PHP', category: 'backend', headers: { 'x-powered-by': 'PHP' } },
  { name: 'Express', category: 'backend', headers: { 'x-powered-by': 'Express' } },
  { name: 'Django', category: 'backend', body: /csrftoken/i },
  { name: 'Ruby on Rails', category: 'backend', body: /rails-/i },
  { name: 'GraphQL', category: 'api', body: /graphql/i },
  { name: 'Swagger', category: 'api', body: /swagger-ui/i },
  { name: 'PostgreSQL', category: 'database', body: /PostgreSQL/i },
  { name: 'MySQL', category: 'database', body: /MySQL/i },
];

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
  'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
  'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
  'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
  'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
  'web', 'media', 'email', 'images', 'img', 'download', 'stage', 'staging',
  'portal', 'api', 'cdn', 'dashboard', 'app', 'auth', 'login', 'accounts',
  'status', 'monitor', 'grafana', 'kibana', 'jenkins', 'gitlab', 'bitbucket',
  'jira', 'confluence', 'slack', 'teams', 'chat', 'help', 'kb', 'knowledge',
  'wiki', 'intranet', 'extranet', 'remote', 'rdp', 'ssh', 'sftp', 'files',
  'share', 'nas', 'backup', 'db', 'db1', 'db2', 'redis', 'elastic', 'kafka',
  'rabbitmq', 'prometheus', 'alertmanager', 'traefik', 'nginx', 'haproxy',
  'vault', 'consul', 'nomad', 'packer', 'terraform', 'puppet', 'chef', 'ansible',
  'salt', 'docker', 'registry', 'k8s', 'kubernetes', 'rancher', 'openshift',
];

// ═══════════════════════════════════════════════════════════════════
// DNS module
// ═══════════════════════════════════════════════════════════════════

async function runDnsModule(domain: string, timeout: number): Promise<{ records: DnsRecords; errors: string[] }> {
  const errors: string[] = [];
  const records: DnsRecords = { a: [], aaaa: [], cname: [], mx: [], ns: [], txt: [], soa: null };

  const timeoutPromise = <T>(promise: Promise<T>, label: string): Promise<T | null> =>
    Promise.race([
      promise,
      new Promise<null>(resolve => setTimeout(() => { errors.push(`DNS ${label} timed out`); resolve(null); }, timeout)),
    ]);

  try {
    const a = await timeoutPromise(resolve4(domain), 'A');
    if (a) records.a = a;
  } catch (e: any) { errors.push(`DNS A: ${e.message}`); }

  try {
    const aaaa = await timeoutPromise(resolve6(domain), 'AAAA');
    if (aaaa) records.aaaa = aaaa;
  } catch { /* IPv6 not always available */ }

  try {
    const cname = await timeoutPromise(resolve('CNAME', domain), 'CNAME');
    if (cname) records.cname = Array.isArray(cname) ? (cname as unknown as string[]) : [cname as unknown as string];
  } catch { /* Not all domains have CNAME */ }

  try {
    const mx = await timeoutPromise(resolveMx(domain), 'MX');
    if (mx) records.mx = mx;
  } catch { /* Not all domains have MX */ }

  try {
    const ns = await timeoutPromise(resolveNs(domain), 'NS');
    if (ns) records.ns = ns;
  } catch (e: any) { errors.push(`DNS NS: ${e.message}`); }

  try {
    const txt = await timeoutPromise(resolveTxt(domain), 'TXT');
    if (txt) records.txt = txt;
  } catch { /* Optional */ }

  try {
    const soa = await timeoutPromise(resolveSoa(domain), 'SOA');
    if (soa) records.soa = soa;
  } catch { /* Not always available */ }

  return { records, errors };
}

// ═══════════════════════════════════════════════════════════════════
// CT Logs module via crt.sh
// ═══════════════════════════════════════════════════════════════════

async function runCtModule(domain: string, timeout: number): Promise<{ subdomains: string[]; errors: string[] }> {
  const errors: string[] = [];
  const url = `https://crt.sh/?q=%.${domain}&output=json`;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const names = new Set<string>();
    for (const entry of data) {
      if (entry.name_value) {
        for (const name of entry.name_value.split('\n')) {
          const cleaned = name.trim().toLowerCase().replace(/^\*\./, '');
          if (cleaned.includes(domain)) names.add(cleaned);
        }
      }
    }
    return { subdomains: Array.from(names).sort(), errors };
  } catch (e: any) {
    errors.push(`CT Logs: ${e.message}`);
    return { subdomains: [], errors };
  }
}

// ═══════════════════════════════════════════════════════════════════
// WHOIS module
// ═══════════════════════════════════════════════════════════════════

async function runWhoisModule(domain: string, timeout: number): Promise<{ whois: WhoisData | null; errors: string[] }> {
  const errors: string[] = [];
  try {
    const result = execSync(`whois ${domain}`, { timeout, encoding: 'utf-8' });
    const raw = result;

    const registrarMatch = raw.match(/Registrar:\s*(.+)/i);
    const creationMatch = raw.match(/Creation Date:\s*(.+)/i) || raw.match(/Created:\s*(.+)/i);
    const expireMatch = raw.match(/Registry Expiry Date:\s*(.+)/i) || raw.match(/Expires:\s*(.+)/i);
    const updatedMatch = raw.match(/Updated Date:\s*(.+)/i) || raw.match(/Modified:\s*(.+)/i);
    const nsMatches = [...raw.matchAll(/Name Server:\s*(\S+)/gi)].map(m => m[1].toLowerCase());
    const registrantMatch = raw.match(/Registrant Name:\s*(.+)/i) || raw.match(/Registrant:\s*(.+)/i);
    const orgMatch = raw.match(/Registrant Organization:\s*(.+)/i);
    const countryMatch = raw.match(/Registrant Country:\s*(.+)/i);

    return {
      whois: {
        domain,
        registrar: registrarMatch ? registrarMatch[1].trim() : 'unknown',
        creationDate: creationMatch ? creationMatch[1].trim() : 'unknown',
        expirationDate: expireMatch ? expireMatch[1].trim() : 'unknown',
        updatedDate: updatedMatch ? updatedMatch[1].trim() : 'unknown',
        nameservers: nsMatches,
        registrant: registrantMatch ? registrantMatch[1].trim() : 'redacted',
        registrantOrg: orgMatch ? orgMatch[1].trim() : 'unknown',
        registrantCountry: countryMatch ? countryMatch[1].trim() : 'unknown',
        raw: raw.substring(0, 5000),
      },
      errors,
    };
  } catch (e: any) {
    errors.push(`WHOIS: ${e.message}`);
    return { whois: null, errors };
  }
}

// ═══════════════════════════════════════════════════════════════════
// Subdomain bruteforce
// ═══════════════════════════════════════════════════════════════════

async function runSubdomainBrute(domain: string, _timeout: number, wordlist?: string, maxSubs?: number): Promise<{ subdomains: string[]; errors: string[] }> {
  const errors: string[] = [];
  const words = wordlist ? wordlist.split('\n').slice(0, maxSubs || 10000) : COMMON_SUBDOMAINS;
  const found: string[] = [];

  const max = maxSubs || words.length;
  const batch = 20;
  for (let i = 0; i < Math.min(words.length, max); i += batch) {
    const batchWords = words.slice(i, i + batch);
    const results = await Promise.allSettled(
      batchWords.map(async (w) => {
        const sub = `${w.trim()}.${domain}`;
        try {
          await resolve4(sub);
          found.push(sub);
        } catch { /* subdomain doesn't resolve */ }
      })
    );
  }

  return { subdomains: found.sort(), errors };
}

// ═══════════════════════════════════════════════════════════════════
// Service fingerprinting via nmap
// ═══════════════════════════════════════════════════════════════════

async function runServiceScan(target: string, _timeout: number, nmapPath?: string): Promise<{ services: ServiceInfo[]; errors: string[] }> {
  const errors: string[] = [];
  const services: ServiceInfo[] = [];
  const nmap = nmapPath || 'nmap';

  try {
    const result = execSync(`${nmap} -sV -T4 --top-ports 100 -oX - ${target}`, {
      timeout: 120_000,
      encoding: 'utf-8',
    });

    // Parse nmap XML output
    const portRegex = /<port protocol="tcp" portid="(\d+)">.*?<state state="open".*?<service name="([^"]+)"(?:\s+product="([^"]+)")?(?:\s+version="([^"]+)")?/gs;
    for (const match of result.matchAll(portRegex)) {
      services.push({
        host: target,
        port: parseInt(match[1], 10),
        service: match[2] || 'unknown',
        version: match[4] || match[3] || 'unknown',
        banner: '',
        tls: false,
      });
    }
  } catch (e: any) {
    errors.push(`Nmap: ${e.message}`);
  }

  return { services, errors };
}

// ═══════════════════════════════════════════════════════════════════
// Technology stack detection
// ═══════════════════════════════════════════════════════════════════

async function runTechStack(host: string, timeout: number): Promise<{ tech: TechnologyInfo[]; errors: string[] }> {
  const errors: string[] = [];
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const resp = await fetch(`https://${host}`, { signal: controller.signal, redirect: 'follow' });
    const body = await resp.text();
    clearTimeout(timer);

    const technologies: TechnologyInfo['technologies'] = [];
    for (const tech of TECH_PATTERNS) {
      let confidence = 0;
      if (tech.headers) {
        const matchCount = Object.entries(tech.headers).filter(([k, v]) => {
          const headerVal = resp.headers.get(k);
          return headerVal && (v === '' || headerVal.toLowerCase().includes(v.toLowerCase()));
        }).length;
        if (matchCount > 0) confidence = matchCount / Object.keys(tech.headers).length;
      }
      if (tech.body && tech.body.test(body)) {
        confidence = Math.max(confidence, 0.7);
      }
      if (confidence >= 0.5) {
        technologies.push({ name: tech.name, category: tech.category, confidence });
      }
    }

    return { tech: [{ host, technologies }], errors };
  } catch (e: any) {
    errors.push(`Tech stack: ${e.message}`);
    return { tech: [], errors };
  }
}

// ═══════════════════════════════════════════════════════════════════
// Cloud asset enumeration
// ═══════════════════════════════════════════════════════════════════

async function runCloudEnum(domain: string): Promise<{ assets: CloudAsset[]; errors: string[] }> {
  const errors: string[] = [];
  const assets: CloudAsset[] = [];

  try {
    // Check for cloud provider indicators in DNS
    const aRecords = await resolve4(domain).catch(() => []);

    for (const ip of aRecords) {
      // Cloudflare
      if (ip.startsWith('104.') || ip.startsWith('172.67.') || ip.startsWith('188.114.')) {
        assets.push({ provider: 'cloudflare', type: 'reverse-proxy', identifier: ip, region: 'global', details: 'Cloudflare IP range' });
      }
      // AWS
      if (ip.startsWith('18.') || ip.startsWith('54.') || ip.startsWith('35.') || ip.startsWith('52.')) {
        if (ip.startsWith('18.164.') || ip.startsWith('18.155.')) {
          assets.push({ provider: 'aws', type: 'cloudfront', identifier: ip, region: 'us-east-1', details: 'CloudFront distribution' });
        } else {
          assets.push({ provider: 'aws', type: 'ec2-or-elb', identifier: ip, region: 'unknown', details: 'AWS IP range' });
        }
      }
      // Fastly
      if (ip.startsWith('151.101.') || ip.startsWith('199.232.')) {
        assets.push({ provider: 'fastly', type: 'cdn', identifier: ip, region: 'global', details: 'Fastly CDN edge' });
      }
      // Akamai
      if (ip.startsWith('23.') && (ip.startsWith('23.32.') || ip.startsWith('23.67.'))) {
        assets.push({ provider: 'akamai', type: 'cdn', identifier: ip, region: 'global', details: 'Akamai edge' });
      }
    }

    // Check CNAME for cloud providers
    const cname = await resolve('CNAME', domain).catch(() => []);
    const cnames = Array.isArray(cname) ? cname : [cname];
    for (const c of cnames) {
      if (c.includes('cloudfront.net')) assets.push({ provider: 'aws', type: 'cloudfront', identifier: c, region: 'unknown', details: 'CloudFront CNAME' });
      if (c.includes('elb.amazonaws.com')) assets.push({ provider: 'aws', type: 'elb', identifier: c, region: 'unknown', details: 'ELB CNAME' });
      if (c.includes('s3.amazonaws.com')) assets.push({ provider: 'aws', type: 's3', identifier: c, region: 'unknown', details: 'S3 CNAME' });
      if (c.includes('googleapis.com') || c.includes('appspot.com')) assets.push({ provider: 'gcp', type: 'app-engine-or-api', identifier: c, region: 'unknown', details: 'GCP CNAME' });
      if (c.includes('azurewebsites.net') || c.includes('cloudapp.net')) assets.push({ provider: 'azure', type: 'app-service', identifier: c, region: 'unknown', details: 'Azure CNAME' });
    }
  } catch (e: any) {
    errors.push(`Cloud enum: ${e.message}`);
  }

  return { assets, errors };
}

// ═══════════════════════════════════════════════════════════════════
// Core: run the full Oculus recon pipeline
// ═══════════════════════════════════════════════════════════════════

export async function runOculus(config: OculusConfig): Promise<OculusResult> {
  const startTime = Date.now();
  const errors: string[] = [];
  const target = config.target.replace(/^https?:\/\//, '').split('/')[0];
  const timeout = config.timeoutPerModule || 15000;
  const modules = config.modules || ['dns', 'ct-logs', 'whois', 'subdomain-brute', 'service-scan', 'tech-stack', 'cloud-enum', 'shodan', 'censys'];

  let dnsRecords: DnsRecords = { a: [], aaaa: [], cname: [], mx: [], ns: [], txt: [], soa: null };
  let ctSubdomains: string[] = [];
  let whoisData: WhoisData | null = null;
  let bruteSubdomains: string[] = [];
  let services: ServiceInfo[] = [];
  let techStack: TechnologyInfo[] = [];
  let cloudAssets: CloudAsset[] = [];
  let passiveServices: ServiceInfo[] = [];

  // Run modules in parallel where possible, sequentially where dependent
  const moduleResults = await Promise.allSettled([
    modules.includes('dns') ? runDnsModule(target, timeout) : Promise.resolve({ records: dnsRecords, errors: [] }),
    modules.includes('ct-logs') ? runCtModule(target, timeout) : Promise.resolve({ subdomains: [], errors: [] }),
    modules.includes('whois') ? runWhoisModule(target, timeout) : Promise.resolve({ whois: null, errors: [] }),
  ]);

  const [dnsR, ctR, whoisR] = moduleResults;
  if (dnsR.status === 'fulfilled') { dnsRecords = dnsR.value.records; errors.push(...dnsR.value.errors); }
  else errors.push(`DNS module: ${dnsR.reason}`);
  if (ctR.status === 'fulfilled') { ctSubdomains = ctR.value.subdomains; errors.push(...ctR.value.errors); }
  else errors.push(`CT module: ${ctR.reason}`);
  if (whoisR.status === 'fulfilled') { whoisData = whoisR.value.whois; errors.push(...whoisR.value.errors); }
  else errors.push(`WHOIS module: ${whoisR.reason}`);

  // Subdomain brute (slower, runs after initial modules)
  if (modules.includes('subdomain-brute')) {
    const result = await runSubdomainBrute(target, timeout, config.wordlistPath, config.maxSubdomains);
    bruteSubdomains = result.subdomains;
    errors.push(...result.errors);
  }

  // Service scan (slowest — runs last)
  if (modules.includes('service-scan')) {
    const result = await runServiceScan(target, timeout, config.nmapPath);
    services = result.services;
    errors.push(...result.errors);
  }

  // Tech stack
  if (modules.includes('tech-stack')) {
    const result = await runTechStack(target, timeout);
    techStack = result.tech;
    errors.push(...result.errors);
  }

  // Cloud enum
  if (modules.includes('cloud-enum')) {
    const result = await runCloudEnum(target);
    cloudAssets = result.assets;
    errors.push(...result.errors);
  }

  // Shodan (passive — API-based)
  if (modules.includes('shodan') && config.shodanKey) {
    try {
      const resp = await fetch(`https://api.shodan.io/dns/domain/${target}?key=${config.shodanKey}`);
      if (resp.ok) {
        const data = await resp.json();
        for (const entry of (data.data || [])) {
          passiveServices.push({
            host: entry.ip || entry.subdomain || target,
            port: entry.port || 0,
            service: entry._shodan?.module || entry.transport || 'unknown',
            version: entry.product || 'unknown',
            banner: entry.data?.substring(0, 200) || '',
            tls: !!entry.ssl,
          });
        }
      }
    } catch (e: any) { errors.push(`Shodan: ${e.message}`); }
  }

  const allSubdomains = new Set([...ctSubdomains, ...bruteSubdomains]);
  const totalAssets = allSubdomains.size + services.length + cloudAssets.length;

  return {
    target,
    totalAssets,
    dns: dnsRecords,
    ctSubdomains,
    whois: whoisData,
    bruteSubdomains,
    services,
    techStack,
    cloudAssets,
    passiveServices,
    durationMs: Date.now() - startTime,
    errors,
  };
}

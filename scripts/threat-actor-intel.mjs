#!/usr/bin/env node
// Threat Actor Intelligence — DeepSeek v4 Pro + Tavily powered when keys exist.
// Generates a public CNE-only fallback for the /threats dashboard.

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const OUT_DIR = join(process.cwd(), 'site', 'vigil-web', 'public', 'threats');
const PROFILES_FILE = join(OUT_DIR, 'profiles.json');
const DEEPSEEK_KEY = process.env.DEEPSEEK_API_KEY || '';
const TAVILY_KEY = process.env.TAVILY_API_KEY || '';
const DEEPSEEK_MODEL = 'deepseek-v4-pro';
const args = new Set(process.argv.slice(2));
const offline = args.has('--offline') || args.has('--no-ai') || !DEEPSEEK_KEY || !TAVILY_KEY;
const limitArg = process.argv.find((arg) => arg.startsWith('--limit='));
const limit = limitArg ? Math.max(1, Number(limitArg.split('=')[1]) || 0) : Infinity;

const ACTORS = [
  ['tailored-tornado', 'Tailored Tornado (NSA CNO public reporting)', 'United States', ['TAO', 'Equation Group', 'Longhorn'], 'Historical public CNO reporting', 'Government, telecom, research, security education', 'Watch', ['T1190', 'T1059', 'T1105', 'T1071', 'T1027', 'T1562']],
  ['forest-blizzard', 'Forest Blizzard (APT28)', 'Russia', ['Fancy Bear', 'Strontium', 'Sofacy'], 'GRU', 'Government, NATO, elections, defense policy', 'Elevated', ['T1566', 'T1110', 'T1078', 'T1059', 'T1105']],
  ['midnight-blizzard', 'Midnight Blizzard (APT29)', 'Russia', ['Cozy Bear', 'Nobelium', 'The Dukes'], 'SVR', 'Diplomatic, cloud identity, supply chain', 'Elevated', ['T1195', 'T1566', 'T1110', 'T1078', 'T1098']],
  ['seashell-blizzard', 'Seashell Blizzard (Sandworm)', 'Russia', ['Sandworm', 'Voodoo Bear', 'TeleBots'], 'GRU Unit 74455', 'ICS, energy, Ukraine critical infrastructure', 'Watch', ['T0882', 'T1485', 'T1490', 'T1566', 'T1105']],
  ['aqua-blizzard', 'Aqua Blizzard (Gamaredon)', 'Russia', ['Gamaredon', 'Primitive Bear', 'Shuckworm'], 'FSB', 'Ukraine government, military, NGOs', 'Tracked', ['T1566', 'T1059.001', 'T1204', 'T1091', 'T1105']],
  ['cadet-blizzard', 'Cadet Blizzard (APT44)', 'Russia', ['DEV-0586', 'UAC-0028'], 'GRU', 'Ukraine, defense, logistics, humanitarian', 'Watch', ['T1566', 'T1485', 'T1490', 'T1005', 'T1105']],
  ['turla', 'Turla (Venomous Bear)', 'Russia', ['Snake', 'Uroburos', 'Secret Blizzard'], 'FSB', 'Diplomatic, government, military, research', 'Tracked', ['T1189', 'T1059', 'T1027', 'T1105', 'T1071']],
  ['berserk-bear', 'Berserk Bear (Dragonfly)', 'Russia', ['Energetic Bear', 'Crouching Yeti'], 'FSB', 'Energy, nuclear, ICS/SCADA', 'Tracked', ['T1195', 'T1189', 'T1190', 'T1078', 'T1021']],
  ['star-blizzard', 'Star Blizzard (Callisto Group)', 'Russia', ['COLDRIVER', 'SEABORGIUM', 'UNC4057'], 'FSB-linked reporting', 'NGOs, journalists, academia, political targets', 'Tracked', ['T1566', 'T1110', 'T1078', 'T1585', 'T1598']],
  ['ghost-blizzard', 'Ghost Blizzard (AridViper / APT-C-23)', 'Middle East', ['AridViper', 'Desert Falcon', 'Micropsia'], 'State-aligned reporting', 'Middle East government, civil society, military', 'Tracked', ['T1566', 'T1204', 'T1059', 'T1105', 'T1437']],
  ['volt-typhoon', 'Volt Typhoon', 'PRC', ['Bronze Starlight', 'VANGUARD PANDA'], 'PRC state security reporting', 'Critical infrastructure and edge devices', 'Elevated', ['T1190', 'T1078', 'T1059', 'T1047', 'T1090']],
  ['brass-typhoon', 'Brass Typhoon (APT41)', 'PRC', ['APT41', 'BARIUM', 'Wicked Panda', 'Winnti'], 'MSS-linked dual mission', 'Supply chain, healthcare, telecom, software', 'Elevated', ['T1195', 'T1190', 'T1078', 'T1059', 'T1027']],
  ['silk-typhoon', 'Silk Typhoon (Hafnium)', 'PRC', ['HAFNIUM', 'HOLMIUM'], 'MSS', 'Email servers, defense, think tanks', 'Elevated', ['T1190', 'T1505', 'T1078', 'T1059', 'T1105']],
  ['granite-typhoon', 'Granite Typhoon (APT10)', 'PRC', ['APT10', 'Stone Panda', 'MenuPass'], 'PRC state-aligned reporting', 'MSPs, aerospace, telecom, government', 'Elevated', ['T1195', 'T1566', 'T1078', 'T1059', 'T1105']],
  ['crimson-typhoon', 'Crimson Typhoon (APT31)', 'PRC', ['APT31', 'ZIRCONIUM', 'Judgment Panda'], 'MSS', 'Government, dissidents, elections, maritime', 'Tracked', ['T1189', 'T1566', 'T1078', 'T1059', 'T1105']],
  ['gallium', 'GALLIUM (APT27)', 'PRC', ['APT27', 'Bronze Union', 'Emissary Panda'], 'PRC state-aligned reporting', 'Telecom, satellite, aviation, healthcare', 'Tracked', ['T1190', 'T1566', 'T1078', 'T1059', 'T1105']],
  ['storm-0558', 'Storm-0558 (Silver Typhoon)', 'PRC', ['Silver Typhoon', 'Mango Storm'], 'MSS reporting', 'Email systems and Microsoft 365 tenants', 'Elevated', ['T1078', 'T1550', 'T1098', 'T1114', 'T1528']],
  ['apt40', 'APT40 (Leviathan)', 'PRC', ['Leviathan', 'TEMP.Periscope', 'Bronco'], 'PRC state-aligned reporting', 'Maritime, naval, defense, engineering', 'Tracked', ['T1190', 'T1566', 'T1059', 'T1105', 'T1005']],
  ['apt19', 'APT19 (Codoso)', 'PRC', ['Codoso Team', 'Deep Panda', 'C0d0so0'], 'PRC state-aligned reporting', 'Law firms, finance, defense contractors', 'Tracked', ['T1189', 'T1566', 'T1059', 'T1105', 'T1078']],
  ['apt18', 'APT18 (Dynamite Panda)', 'PRC', ['Dynamite Panda', 'TG-0416', 'Wekby'], 'PLA reporting', 'Aerospace, defense, technology, healthcare', 'Tracked', ['T1566', 'T1190', 'T1059', 'T1105', 'T1078']],
  ['ke3chang', 'Ke3chang (APT15)', 'PRC', ['APT15', 'Mirage', 'Vixen Panda'], 'MSS', 'Government, defense, diplomatic targets', 'Tracked', ['T1566', 'T1059', 'T1105', 'T1071', 'T1027']],
  ['apt30', 'APT30 (Naikon)', 'PRC', ['Naikon', 'Overlord', 'NEC Group'], 'MSS', 'ASEAN government, military, maritime', 'Tracked', ['T1566', 'T1059', 'T1105', 'T1071', 'T1005']],
  ['mustang-panda', 'Mustang Panda', 'PRC', ['Bronze President', 'TA416', 'RedDelta'], 'PRC state-aligned reporting', 'Government, NGOs, diplomatic missions', 'Elevated', ['T1566', 'T1204', 'T1059', 'T1105', 'T1574']],
  ['luminousmoth', 'LuminousMoth (APT-C-09)', 'PRC', ['HoneyMyte', 'Sugarload'], 'MSS reporting', 'Myanmar and Southeast Asian government', 'Tracked', ['T1566', 'T1059', 'T1574', 'T1105', 'T1005']],
  ['deep-panda', 'Deep Panda (APT1 / Comment Crew)', 'PRC', ['APT1', 'Comment Crew', 'TG-8223'], 'PLA Unit 61398 reporting', 'Defense, aerospace, manufacturing', 'Tracked', ['T1566', 'T1059', 'T1105', 'T1078', 'T1005']],
  ['diamond-sleet', 'Diamond Sleet (Lazarus Group)', 'DPRK', ['Lazarus', 'ZINC', 'HIDDEN COBRA'], 'Reconnaissance General Bureau', 'Crypto, finance, defense, supply chain', 'Elevated', ['T1195', 'T1566', 'T1204', 'T1059', 'T1105']],
  ['emerald-sleet', 'Emerald Sleet (Kimsuky)', 'DPRK', ['Kimsuky', 'Velvet Chollima', 'THALLIUM'], 'Reconnaissance General Bureau', 'Think tanks, academia, nuclear policy', 'Tracked', ['T1566', 'T1204', 'T1059', 'T1105', 'T1114']],
  ['onyx-sleet', 'Onyx Sleet (Andariel)', 'DPRK', ['Andariel', 'Silent Chollima', 'Stonefly'], 'Reconnaissance General Bureau', 'Defense, aerospace, healthcare', 'Tracked', ['T1190', 'T1566', 'T1059', 'T1105', 'T1486']],
  ['ruby-sleet', 'Ruby Sleet (Bluenoroff)', 'DPRK', ['Bluenoroff', 'Stardust Chollima', 'APT38'], 'RGB financial subgroup', 'Banking, crypto exchanges, fintech', 'Tracked', ['T1566', 'T1189', 'T1078', 'T1059', 'T1567']],
  ['ricochet-chollima', 'Ricochet Chollima (APT37)', 'DPRK', ['APT37', 'Reaper', 'ScarCruft'], 'Reconnaissance General Bureau', 'South Korea, defectors, journalists', 'Tracked', ['T1566', 'T1204', 'T1189', 'T1059', 'T1105']],
  ['sapphire-sleet', 'Sapphire Sleet (APT43)', 'DPRK', ['APT43', 'Nickel Academy'], 'Reconnaissance General Bureau', 'Crypto, identity abuse, policy research', 'Tracked', ['T1566', 'T1598', 'T1078', 'T1110', 'T1114']],
  ['mint-sandstorm', 'Mint Sandstorm (APT35)', 'Iran', ['Charming Kitten', 'PHOSPHORUS'], 'IRGC', 'Government, dissidents, elections, academia', 'Elevated', ['T1566', 'T1598', 'T1078', 'T1110', 'T1114']],
  ['crimson-sandstorm', 'Crimson Sandstorm (APT34)', 'Iran', ['OilRig', 'Helix Kitten'], 'MOIS', 'Energy, finance, government, chemical', 'Tracked', ['T1566', 'T1190', 'T1059', 'T1105', 'T1071']],
  ['pink-sandstorm', 'Pink Sandstorm (APT33)', 'Iran', ['Elfin', 'REFINED KITTEN', 'Peach Sandstorm'], 'IRGC', 'Energy, aviation, defense, petrochemical', 'Tracked', ['T1566', 'T1190', 'T1059', 'T1105', 'T1485']],
  ['muddywater', 'MuddyWater (Mercury)', 'Iran', ['MERCURY', 'Seedworm', 'Static Kitten'], 'MOIS', 'Government, telecom, education', 'Tracked', ['T1566', 'T1059.001', 'T1219', 'T1105', 'T1078']],
  ['apt39', 'APT39 (Chafer)', 'Iran', ['Chafer', 'Remix Kitten', 'Crambus'], 'MOIS', 'Telecom, travel, IT services', 'Tracked', ['T1190', 'T1059', 'T1105', 'T1078', 'T1005']],
  ['dev-0343', 'DEV-0343', 'Iran', ['DEV-0343'], 'IRGC-affiliated reporting', 'Defense and Microsoft 365 tenants', 'Tracked', ['T1110', 'T1078', 'T1087', 'T1090', 'T1589']],
  ['darkhydrus', 'DarkHydrus (APT-C-35)', 'Iran', ['DarkHydrus', 'Lazy Kitten', 'xHunt'], 'MOIS-aligned reporting', 'Government, education, energy', 'Tracked', ['T1566', 'T1059', 'T1110', 'T1078', 'T1105']],
  ['copykittens', 'CopyKittens (APT-C-23 / Rocket Kitten)', 'Iran', ['Rocket Kitten', 'Cobalt Gypsy'], 'IRGC reporting', 'Israel, defense, diplomatic targets', 'Tracked', ['T1566', 'T1059', 'T1105', 'T1078', 'T1437']],
  ['scattered-spider', 'Scattered Spider (Octo Tempest)', 'E-crime', ['0ktapus', 'UNC3944', 'Muddled Libra'], 'Criminal ecosystem reporting', 'SaaS identity, telecom, help desks', 'Elevated', ['T1566.002', 'T1589', 'T1078', 'T1098', 'T1110']],
  ['fin7', 'FIN7 (Sangria Tempest)', 'E-crime', ['Carbanak', 'Navigator Group', 'Anunak'], 'Criminal organization', 'POS, hospitality, retail, ransomware delivery', 'Tracked', ['T1566', 'T1091', 'T1059', 'T1105', 'T1486']],
  ['fin11', 'FIN11 (Lace Tempest)', 'E-crime', ['Lace Tempest', 'TA505', 'Cl0p affiliate group'], 'Criminal organization', 'Managed file-transfer and data extortion', 'Tracked', ['T1190', 'T1566', 'T1059', 'T1105', 'T1041']],
  ['alphv', 'ALPHV/BlackCat', 'E-crime', ['ALPHV', 'BlackCat', 'Noberus'], 'Ransomware affiliate network', 'Healthcare, education, critical infrastructure', 'Elevated', ['T1078', 'T1021', 'T1486', 'T1490', 'T1567']],
  ['cl0p', 'CL0P Ransomware', 'E-crime', ['CL0P', 'Clop', 'TA505 overlap'], 'Criminal syndicate', 'Managed file-transfer and enterprise software', 'Elevated', ['T1190', 'T1005', 'T1041', 'T1567', 'T1486']],
  ['lockbit', 'LockBit', 'E-crime', ['LockBit 3.0', 'Bitwise Spider'], 'Ransomware affiliate ecosystem', 'Global enterprise ransomware and data extortion', 'Watch', ['T1078', 'T1021', 'T1486', 'T1490', 'T1567']],
  ['apt32', 'APT32 (OceanLotus)', 'Vietnam', ['OceanLotus', 'Canvas Cyclone', 'SeaLotus'], 'Vietnam state-aligned reporting', 'Manufacturing, maritime, media, dissidents', 'Tracked', ['T1189', 'T1566', 'T1059', 'T1105', 'T1005']],
  ['apt36', 'APT36 (Transparent Tribe)', 'Pakistan', ['Transparent Tribe', 'Mythic Leopard'], 'Pakistan state-aligned reporting', 'Indian government and military', 'Elevated', ['T1566', 'T1204', 'T1059', 'T1105', 'T1437']],
  ['sidewinder', 'SideWinder (APT-C-17)', 'India-aligned', ['Rattlesnake', 'Razor Tiger'], 'India-aligned reporting', 'South Asian military and government', 'Tracked', ['T1566', 'T1059', 'T1105', 'T1071.004', 'T1005']],
  ['patchwork', 'Patchwork (APT-C-09)', 'India-aligned', ['Dropping Elephant', 'Quilted Tiger'], 'India-aligned reporting', 'China and Pakistan government targets', 'Tracked', ['T1566', 'T1059', 'T1105', 'T1078', 'T1005']],
  ['ghostwriter', 'Ghostwriter (UNC1151 / APT28-hybrid)', 'Belarus-aligned', ['UNC1151', 'Pushcha', 'TA499'], 'Belarus state-aligned reporting', 'NATO, EU, Eastern Europe', 'Tracked', ['T1585', 'T1566', 'T1078', 'T1114', 'T1598']],
  ['earth-kitsune', 'Earth Kitsune (Agrius / APT-C-36 overlap)', 'Middle East', ['Earth Kitsune', 'Agrius'], 'Suspected Iran nexus reporting', 'Israel, data destruction, deception', 'Tracked', ['T1566', 'T1059', 'T1485', 'T1490', 'T1005']],
  ['blind-eagle', 'Blind Eagle (APT-C-36)', 'Colombia', ['APT-C-36', 'Blind Eagle'], 'Colombia state-aligned reporting', 'Latin American government and finance', 'Tracked', ['T1566', 'T1204', 'T1059', 'T1105', 'T1078']],
  ['el-machete', 'El Machete', 'Latin America', ['Machete', 'APT-C-33'], 'Latin America state-aligned reporting', 'Government, military, diplomatic targets', 'Tracked', ['T1566', 'T1091', 'T1059.006', 'T1105', 'T1005']],
  ['dark-caracal', 'Dark Caracal', 'Lebanon', ['Dark Caracal', 'Operation DustySky'], 'Lebanese GID-aligned reporting', 'Middle East government and journalists', 'Tracked', ['T1566', 'T1204', 'T1059', 'T1105', 'T1437']],
  ['bahamut', 'Bahamut (APT-C-24)', 'Middle East', ['Bahamut', 'APT-C-24'], 'Middle East state-aligned reporting', 'Diplomatic, human-rights, mobile users', 'Tracked', ['T1566', 'T1204', 'T1437', 'T1418', 'T1078']],
  ['gorgon-group', 'Gorgon Group', 'E-crime', ['Subaat', 'Gorgon'], 'Criminal and Pakistan-aligned reporting', 'Government, financial, global business', 'Tracked', ['T1566', 'T1204', 'T1059', 'T1105', 'T1078']],
  ['smoking-spider', 'Smoking Spider (UNC1945 / APT28-L2 case import)', 'E-crime', ['UNC1945', 'Smoking Spider', 'APT28-L2'], 'Criminal with possible state overlap', 'Telecom, hosting providers, extortion', 'Tracked', ['T1190', 'T1059', 'T1105', 'T1090', 'T1498']],
];

function toActor(row) {
  const [id, name, country, aliases, sponsor, focus, status, attck] = row;
  return {
    id,
    name,
    country,
    aliases,
    sponsor,
    focus,
    status,
    attck,
    techniques: attck,
    sectors: focus.split(',').map((value) => value.trim()).filter(Boolean).slice(0, 5),
    tools: [],
    regions: [country],
    motivation: sponsor,
    recentActivity: 'Static CNE fallback generated from the consolidated /threats registry. Live Tavily and DeepSeek enrichment hydrates this profile when API keys are available.',
    defensivePriorities: [
      'Collect identity, endpoint, cloud, DNS, proxy, and case-evidence telemetry before tuning actor-specific detections.',
      'Map public reporting to MITRE ATT&CK and maintain confidence labels separately from remediation urgency.',
      'Keep public output limited to defensive summaries, source links, hardening priorities, and telemetry requirements.',
    ],
    lastUpdated: new Date().toISOString(),
    sourceMode: offline ? 'static-fallback' : 'seed-before-live-enrichment',
  };
}

async function tavilySearch(actor) {
  if (offline) return [];
  const response = await fetch('https://api.tavily.com/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      api_key: TAVILY_KEY,
      query: `${actor.name} public cyber threat intelligence defensive analysis 2026`,
      search_depth: 'advanced',
      max_results: 5,
      include_answer: true,
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) return [];
  const data = await response.json();
  return data.results || [];
}

async function deepseekAnalyze(actor, results) {
  if (offline || !results.length) return '';
  const sourceText = results.map((result) => result.content || result.snippet || '').join('\n').slice(0, 5000);
  const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${DEEPSEEK_KEY}` },
    body: JSON.stringify({
      model: DEEPSEEK_MODEL,
      messages: [{
        role: 'user',
        content: `Create a public Computer Network Defense profile for ${actor.name}.

Return defensive summary only. Include MITRE ATT&CK IDs, public CVE references if the sources mention them, malware or tool family names, telemetry to collect, and mitigation priorities.
Do not include operational instructions, payloads, evasion details, credential collection guidance, or live infrastructure indicators such as IPs, domains, account handles, or certificate pivots.

Open-source snippets:
${sourceText}`,
      }],
      max_tokens: 1200,
      temperature: 0.2,
    }),
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) return '';
  const data = await response.json();
  return data.choices?.[0]?.message?.content || '';
}

function sanitize(text) {
  return String(text || '')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[redacted IP]')
    .replace(/\b[a-z0-9-]+(?:\.[a-z0-9-]+){1,4}\.(?:com|net|org|io|ru|cn|ir|kp|ua|uk|gov|mil|edu|co)\b/gi, '[redacted domain]');
}

async function enrich(profile) {
  if (offline) return profile;
  const results = await tavilySearch(profile);
  const analysis = sanitize(await deepseekAnalyze(profile, results));
  return {
    ...profile,
    sources: results.map((result) => ({
      title: String(result.title || '').slice(0, 180),
      url: result.url,
      source: String(result.url || '').match(/https?:\/\/([^/]+)/)?.[1] || 'unknown',
      snippet: sanitize(result.content || result.snippet || '').slice(0, 360),
    })),
    ttpAnalysis: analysis.slice(0, 4000),
    cves: [...new Set(analysis.match(/CVE-\d{4}-\d{4,}/gi) || [])],
    techniques: [...new Set([...(profile.techniques || []), ...(analysis.match(/T\d{4}(?:\.\d{3})?/g) || [])])],
    sourceMode: 'tavily+deepseek-public-cne',
    lastUpdated: new Date().toISOString(),
  };
}

async function main() {
  console.log('[threat-intel] building public CNE threat profiles');
  console.log(`[threat-intel] mode=${offline ? 'static fallback' : 'tavily + deepseek-v4-pro'} actors=${ACTORS.length}`);
  mkdirSync(OUT_DIR, { recursive: true });

  const profiles = [];
  for (const row of ACTORS.slice(0, limit)) {
    const profile = toActor(row);
    console.log(`  ${profiles.length + 1}/${Math.min(ACTORS.length, limit)} ${profile.name}`);
    profiles.push(await enrich(profile));
    if (!offline) await new Promise((resolve) => setTimeout(resolve, 1200));
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    totalActors: profiles.length,
    totalCves: [...new Set(profiles.flatMap((profile) => profile.cves || []))].length,
    totalTechniques: [...new Set(profiles.flatMap((profile) => profile.techniques || []))].length,
    providers: {
      deepseek: DEEPSEEK_KEY ? DEEPSEEK_MODEL : 'not configured locally',
      tavily: TAVILY_KEY ? 'configured locally' : 'not configured locally',
    },
    mode: offline ? 'static-cne-fallback' : 'tavily-deepseek-public-cne',
  };

  const output = {
    summary,
    profiles,
    _meta: {
      generatedAt: summary.generatedAt,
      engine: offline ? 'static CNE fallback; cloud Lambda hydrates with tavily + deepseek-v4-pro' : 'tavily + deepseek-v4-pro',
      mode: summary.mode,
      actorsTracked: profiles.length,
      safety: 'public-cne-only',
    },
  };

  writeFileSync(PROFILES_FILE, JSON.stringify(output, null, 2), 'utf8');
  console.log(`[threat-intel] wrote ${PROFILES_FILE}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

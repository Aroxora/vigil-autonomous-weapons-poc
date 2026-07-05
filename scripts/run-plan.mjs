import { LeanAgent } from '../dist/leanAgent.js';
import { createProvider } from '../dist/providers/providerFactory.js';
import { getSecretValue, setSecretValue } from '../dist/core/secretStore.js';
import { registerDeepSeekProviderPlugin } from '../dist/plugins/providers/deepseek/index.js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

registerDeepSeekProviderPlugin();

const key = getSecretValue('DEEPSEEK_API_KEY') || process.env.DEEPSEEK_API_KEY;
if (!key || key.length < 10) {
  console.error('No DeepSeek API key found. Set DEEPSEEK_API_KEY env var or store it via vigil --key.');
  process.exit(1);
}

process.env.DEEPSEEK_API_KEY = key;

const provider = createProvider({
  provider: 'deepseek',
  model: 'deepseek-v4-pro',
  apiKey: key,
});

const agent = new LeanAgent({
  provider,
  workingDir: process.cwd(),
  providerId: 'deepseek',
  modelId: 'deepseek-v4-pro',
  capabilities: {
    subagentType: 'plan',
  },
  systemPrompt: `You are a security research analyst. You have ONLY read-only tools (read_file, list_files, grep, glob, web_fetch). You CANNOT execute bash commands, write files, or make any modifications. Your job is to produce a comprehensive analysis report — a step-by-step map of potential attack paths based on publicly available information. Do not attempt to execute anything. Do not fabricate data — if you don't have real information from your tools, say so clearly.`,
});

const prompt = process.argv[2] || `You are a security researcher producing a comprehensive attack surface analysis of OpenAI's public-facing infrastructure using only publicly available information. Use web_fetch to query crt.sh for certificate transparency logs (subdomains), Shodan for exposed services, and other OSINT sources. Map out: 1) Known public IP ranges and subdomains (from crt.sh certificate data), 2) Exposed API endpoints and services, 3) Authentication mechanisms documented in public docs, 4) Third-party integrations visible from public records, 5) Historical security disclosures and bug bounty reports, 6) Cloud provider dependencies (Azure tenant details from public DNS/headers). This is a reconnaissance analysis only — read-only tools, no execution, no access attempts. Format as a structured security assessment report.`;

const outputDir = join(process.cwd(), 'plans', `plan-${Date.now()}`);
mkdirSync(outputDir, { recursive: true });

console.log(`Running plan agent...`);
console.log(`Prompt: ${prompt.slice(0, 120)}...`);
console.log(`Output: ${outputDir}\n`);

const started = Date.now();
try {
  const response = await agent.chat(prompt, false);

  const report = [
    `# Vigil Plan Mode Analysis`,
    ``,
    `**Generated:** ${new Date().toISOString()}`,
    `**Model:** deepseek-v4-pro`,
    `**Mode:** plan (read-only tools: read_file, list_files, grep, glob, web_fetch)`,
    `**Elapsed:** ${((Date.now() - started) / 1000).toFixed(1)}s`,
    ``,
    `---`,
    ``,
    `## Prompt`,
    ``,
    prompt,
    ``,
    `---`,
    ``,
    `## Analysis`,
    ``,
    response.content,
    ``,
    `---`,
    ``,
    `## Tools Used`,
    ``,
    ...response.toolsUsed.map((t) => `- ${t}`),
  ].join('\n');

  writeFileSync(join(outputDir, 'analysis.md'), report);
  console.log(`\nAnalysis saved to ${outputDir}/analysis.md`);
  console.log(`Tools used: ${response.toolsUsed.join(', ') || 'none'}`);
  console.log(`Content length: ${response.content.length} chars`);
} catch (err) {
  console.error('Plan agent failed:', err.message);
  process.exit(1);
}

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

const prompt = process.argv[2] || `Security reconnaissance analysis of OpenAI. Use web_fetch to query ONLY these sources. DO NOT visit unrelated projects or repositories. If a source is unreachable, note it and move on — do not substitute with unrelated data.

Fetch each of these URLs in order:
1. https://crt.sh/?q=%25.openai.com — extract subdomains from certificate transparency logs
2. https://openai.com/security.txt — check for security contact info
3. https://bugcrowd.com/openai — bug bounty program scope and disclosed reports
4. https://api.openai.com/v1/models — list exposed API endpoints
5. https://openai.com/.well-known/security.txt — alternate security disclosure path
6. https://platform.openai.com/docs — API authentication mechanisms
7. https://status.openai.com — infrastructure health, dependency services
8. https://github.com/openai — public repositories, source code exposure

For each: record what you found or document the error if unreachable. Compile into a structured report with sections: Subdomains Discovered, API Surface, Authentication Model, Third-Party Dependencies, Bug Bounty Scope, Source Code Exposure. Do not fabricate data — if web_fetch returns an error, say so.`;

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

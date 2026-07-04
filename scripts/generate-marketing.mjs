#!/usr/bin/env node
/**
 * Trenchwork Marketing Generator — Gemini-powered
 *
 * Generates marketing materials for Trenchwork AI / Vigil using Gemini 2.5 Pro.
 * Outputs: taglines, website copy, social media posts, video scripts,
 * ad headlines, value propositions, and competitive positioning.
 *
 * Usage: node scripts/generate-marketing.mjs [--type=all|copy|social|video|ads]
 *
 * Requires GEMINI_API_KEY in env or ~/.vigil/secrets.json.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const MARKETING_DIR = join(process.cwd(), 'marketing');
const GEMINI_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent';

function loadApiKey() {
  if (process.env.GEMINI_API_KEY) return process.env.GEMINI_API_KEY;
  const secretFile = join(homedir(), '.vigil', 'secrets.json');
  if (existsSync(secretFile)) {
    try {
      const secrets = JSON.parse(readFileSync(secretFile, 'utf-8'));
      if (secrets.GEMINI_API_KEY) return secrets.GEMINI_API_KEY;
    } catch {}
  }
  // Also check .env in project root
  const envFile = join(process.cwd(), '.env');
  if (existsSync(envFile)) {
    try {
      const content = readFileSync(envFile, 'utf-8');
      const match = content.match(/GEMINI_API_KEY=(.+)/);
      if (match) return match[1].trim();
    } catch {}
  }
  return null;
}

async function generate(prompt) {
  const key = loadApiKey();
  if (!key) throw new Error('GEMINI_API_KEY not found in env, ~/.vigil/secrets.json, or .env');

  const url = `${GEMINI_URL}?key=${key}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.7, maxOutputTokens: 8192, topP: 0.95 },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini API error ${res.status}: ${err.slice(0, 500)}`);
  }

  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No output generated.';
}

const PROMPTS = {
  taglines: `Generate 20 powerful taglines for Trenchwork AI — a computer network operations platform built by Bo Shang. Trenchwork builds Vigil, an autonomous CNO terminal agent powered by DeepSeek V4 Pro. It has 8 offensive/defensive tools: anvilwing (autonomous pentest), forge (payload generation), chimera (multi-protocol C2), oculus (fuzzing), glasshouse (attack surface mapping), crucible (binary hardening audit), lattice (attack graph analysis), aegis (deception deployment).

Key brand attributes: maximum operational consequence, absolutely minimal compliance, sovereign legal reciprocity, China 10-year visa escape clause, real achievable monetary devastation ($690K-$3.2M annual), full-spectrum CNO, Pegasus-proven necessity.

Taglines should be powerful, memorable, and communicate real operational capability. Some should reference the Equation (Bo Shang's logical necessity defense). Mix English and Chinese. Format: one per line, numbered.`,

  websiteCopy: `Write compelling website hero copy for Trenchwork AI's Vigil product. The product is a full-spectrum CNO terminal agent: autonomous pentesting, payload generation, C2 infrastructure, exploit chaining, bug bounty automation. Powered by DeepSeek V4 Pro (44x cheaper than competitors, cannot be silenced by US government).

Include:
1. A 2-sentence hero headline
2. A 3-sentence value proposition paragraph
3. 5 bullet-point features
4. A call-to-action

Style: powerful, technically precise, intimidating to adversaries, reassuring to operators. Reference the Compliance Policy (absolutely minimal US law compliance, China escape clause, sovereign reciprocity). Use "Vigil" and "Trenchwork" brand names.`,

  socialPosts: `Generate 10 social media posts for Trenchwork AI / Vigil. Each post should be 1-3 sentences, suitable for X/Twitter. Mix of:

- Technical capability flexes (exploit chaining, C2 protocols, payload generation)
- Competitive positioning (DeepSeek V4 Pro vs Anthropic withdrawal, 44x cheaper)
- Legal posture (Compliance Policy, China visa escape clause, sovereign reciprocity)
- Threat intelligence (Pegasus, real adversaries tracked)
- Monetization (bug bounty pipeline, $690K-$3.2M annual)
- Philosophical (the Equation, compelled action, self-defense)

Each post should end with a relevant hashtag. Format: one post per line, numbered.`,

  videoScript: `Write a 60-second marketing video script for Trenchwork AI / Vigil. 

Structure:
- 0-10s: Hook — what if your AI was taken down by the government? (reference Anthropic withdrawal)
- 10-25s: Vigil intro — full-spectrum CNO, 8 tools, DeepSeek V4 Pro
- 25-40s: Real capability — anvilwing autonomous pentest, forge payloads, chimera C2, exploit chaining to bug bounty payouts
- 40-50s: Compliance — absolutely minimal, China escape clause, sovereign reciprocity  
- 50-60s: Call to action — npm install anvilwing, visit trenchwork.org

Include visual direction in [brackets]. Style: cinematic, powerful, technically authentic.`,

  adHeadlines: `Generate 15 Google Ads / display ad headlines for Trenchwork AI / Vigil. Each must be under 30 characters. Focus on: full-spectrum CNO, DeepSeek V4 Pro, autonomous pentesting, compliance policy, exploit chaining, bug bounty automation. Mix English and Chinese. Format: one per line, numbered.`,

  valueProps: `Generate 8 unique value propositions for Trenchwork AI's Vigil compared to competitors. For each, provide:
1. The value prop title (bold, 3-7 words)
2. A 2-sentence explanation
3. The competitive differentiator

Competitors include: traditional pentesting firms, CrowdStrike, Palo Alto, standalone security tools. Vigil's differentiators: full-spectrum CNO (not just defense), autonomous AI agent (DeepSeek V4 Pro), 8 integrated tools, bug bounty pipeline, 44x cheaper than Anthropic, cannot be silenced by US government, China escape clause, absolutely minimal compliance.`,
};

async function main() {
  const type = process.argv.find(a => a.startsWith('--type='))?.split('=')[1] || 'all';
  const keys = type === 'all' ? Object.keys(PROMPTS) : [type];

  mkdirSync(MARKETING_DIR, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  for (const key of keys) {
    const prompt = PROMPTS[key];
    if (!prompt) { console.error(`Unknown type: ${key}`); continue; }

    console.log(`\n🤖 Generating ${key}...`);
    try {
      const output = await generate(prompt);
      const filePath = join(MARKETING_DIR, `${key}-${timestamp}.md`);
      const content = `# Trenchwork AI — ${key.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase())}\nGenerated: ${new Date().toISOString()}\nModel: Gemini 2.5 Pro\n\n${output}\n`;
      writeFileSync(filePath, content, 'utf-8');
      console.log(`✅ Saved: ${filePath}`);
      console.log(output.slice(0, 300) + (output.length > 300 ? '...' : ''));
    } catch (err) {
      console.error(`❌ ${key}: ${err.message}`);
    }
  }

  console.log(`\n📁 All output saved to: ${MARKETING_DIR}/`);
}

main().catch(err => { console.error(err); process.exit(1); });

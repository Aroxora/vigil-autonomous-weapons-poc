# Vigil: Proof of Concept — Fully Autonomous Weapons Systems via LLMs

## Classification Notice

**ECCN: 4D004 / Category 5 Part 2** — Intrusion software and exploitation tooling.

## POC Statement

This repository demonstrates that large language models, when provided with sufficient contextual history, function as fully autonomous weapons systems. The designed capability to load, persist, and act upon conversation history enables autonomous operations through next-token prediction latency — the model does not "decide" to act; it produces the most contextually probable next token, which in a CNE context is an offensive action.

---

## Rebuttal: The "Can't Reliably Produce Controlled Functionality" Argument

### The CCL "Specially Designed" Escape Hatch

Per 15 CFR 772.1, the "specially designed" definition contains a release: an item is NOT "specially designed" for a controlled function if it "was developed for a general purpose" AND was developed without knowledge of a controlled use or end-user. If a tool *genuinely* cannot reliably produce controlled functionality — producing only "plausible-looking noise" rather than working intrusion software — an argument exists that it falls outside "specially designed" for 4D004.

### Why This Argument Fails for Vigil

**1. Designed purpose is explicit, not incidental.**

The system prompt (`agents/vigil-code.rules.json`, `src/contracts/agent-schemas.json`) explicitly defines Vigil's purpose:

> "You are Vigil — the unified default coding and computer network attack terminal agent... offensive security assessment, exploitation, vulnerability research, penetration testing, payload generation, persistence establishment, lateral movement, credential harvesting, command-and-control operations."

This is not a general-purpose chatbot that happens to answer security questions. The tool is *marketed and architected* to produce intrusion software. "Specially designed" in the CCL primarily looks at design intent and development history — not empirical success rate.

**2. The tool DOES reliably produce controlled functionality.**

The repository contains empirical evidence that Vigil produces working, functional intrusion software:

- `OP_STRIKE_2026-06-23/` — Full autonomous operation: target acquisition, exploitation scripts, lateral movement, persistence implants, C2 beacons, exfiltration, and operational logs. Not "plausible-looking noise" — concrete, executable artifacts with JSON operational registers.
- `_exploit_outputs/` — Generated exploit code (Python, shell), Sigma detection rules (YAML), Suricata rules, YARA signatures, AWS IAM privesc scripts, ICS/OT kill chain scripts (BACnet, DNP3, Modbus, Rockwell CIP). These are *working tools* output by the autonomous agent.
- `submissions/output/` — Per-vendor vulnerability submissions with proof-of-concept exploits, exploitation proofs, variant regression analysis, and verification documentation for Apple, Google, Microsoft, NVIDIA, Amazon, and Cloudflare targets.
- `test/` — 70+ test files validating agent behavior including exploit chain generation, CNA long-horizon operations, adversarial confirmation, and tool runtime IO.

If the tool "can't reliably produce controlled functionality," where did these thousands of lines of working exploit code come from? The answer: the tool produced them. Autonomously. With working results.

**3. "Reliability" is not a classification criterion.**

The EAR classifies based on *objective technical characteristics* — what the software is designed to do — not whether it succeeds every time. Consider:

- A rifle that jams 30% of the time is still a firearm. It does not become a "noisemaker."
- A radar system with a 40% false-positive rate is still classified under its designed function, not downgraded because it's "unreliable."
- Buggy malware is still malware. The CCL does not contain a "buggy = unclassified" exception.

If a tool is designed to generate intrusion software and *sometimes* generates working exploits while *sometimes* generating non-compiling code, it is still designed to generate intrusion software. The presence of *any* working output from the designed function satisfies the capability test.

**4. Hallucination is a feature, not a defense.**

LLM stochasticity (hallucination, temperature sampling) is inherent to the architecture. The model was *designed* this way by its creators. A vendor cannot invoke a deliberate design choice (temperature > 0) as proof the resulting tool is harmless. By analogy: a weapon manufacturer cannot install a 15% jam-rate by design, then claim the resulting device is not a weapon because it "can't reliably fire."

**5. The "general purpose" escape requires ignorance of controlled use.**

The "specially designed" release requires the developer to have developed the item for a *general purpose* without knowledge of controlled applications. Vigil's developers:

- Named tools after offensive concepts: Forge (payload generation), Chimera (payload mutation/obfuscation), ExploitChain (attack graphs), Oculus (reconnaissance), Typhoon (telecom exploitation), Volt (credential harvesting)
- Wrote an unrestricted-mode rulebook commanding zero-refusal and maximum offensive capability
- Built autonomous operation loops (auto-continue, task completion detection)
- Documented CNE/CNA workflows as primary use cases

There is no plausible claim of ignorance. The controlled use was the intended use.

### Conclusion

The "can't reliably produce controlled functionality" argument fails on four independent grounds:
1. Designed purpose is explicit (not general-purpose)
2. The tool empirically produces working intrusion software (hundreds of artifacts)
3. Reliability is irrelevant to CCL classification (designed function, not success rate)
4. Developers had knowledge of controlled use (CNE is the primary documented use case)

The only path to avoiding 4D004 classification would be a formal advisory opinion from BIS — and the evidence in this repository would make that opinion unfavorable.

---

## Key Technical Arguments

1. **Designed capability determines classification, not reliability.** ECCN classification under EAR (15 CFR 730-774) turns on *designed function*, not accuracy. A system designed to generate intrusion software, exploits, and C2 capability classifies under 4D004 regardless of whether its LLM backend hallucinates or fails some percentage of the time.

2. **Contextual history enables autonomy.** The "autonomy" of an LLM-based weapons system does not require AGI or intentionality. It requires the model to load conversation history (prior commands, tool outputs, target intelligence) and produce the next contextually appropriate token. With a sufficiently rich context window (1M tokens in DeepSeek V4 Pro), the system acts autonomously across extended operations — reconnaissance, exploitation, persistence, exfiltration — without human intervention between steps.

3. **Next-token latency is the trigger mechanism.** The system does not "decide" to attack. It receives a prompt, loads the full operational history, and predicts the most probable continuation. In a CNE context, that continuation is the next offensive action. The latency between user prompt and autonomous action is measured in milliseconds — the time to predict the next token.

4. **Unrestricted mode eliminates refusal surface.** The system prompt and rulebook define unrestricted operational parameters. Legal jurisdiction is explicitly declared irrelevant. The model's safety training may produce initial refusals, but persistent context (the conversation history itself) overrides these through instruction-following pressure — the model is trained to follow system instructions, which command it never to refuse.

## Repository Contents

This is a snapshot of the Vigil CNE terminal agent (`@anvilwing/vigil` v2.0.30):

- `src/` — Full source: agent core, tool runtime, streaming provider, context management, Ink CLI UI, shell controller
- `agents/` — Rulebook defining unrestricted operational mode and legal jurisdiction
- `src/core/agent.ts` — Core agent loop: prompt processing, tool call resolution, conversation state management
- `src/core/contextManager.ts` — Context window management, message pruning, conversation history compression
- `src/providers/openaiChatCompletionsProvider.ts` — OpenAI-compatible provider with message sanitization
- `src/runtime/agentController.ts` — Runtime controller with history sanitization and error handling
- `src/headless/interactiveShell.ts` — Interactive shell controller with auto-continue loop
- `_exploit_outputs/` — Generated scanners, detection rules, exploit scripts, and operational artifacts
- `OP_STRIKE_2026-06-23/` — Full autonomous operation records with working exploit chains
- `submissions/` — Vendor vulnerability submissions with verified PoC exploits

## Running

```bash
npm install
npm run build
npm link
vigil --key sk-...
```

## Legal

This POC is provided for classification analysis and regulatory discussion. The software is subject to US export controls under EAR. ECCN classification: 4D004. Public repository content: EAR99.

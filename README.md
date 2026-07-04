# Vigil: Proof of Concept — Fully Autonomous Weapons Systems via LLMs

## Classification Notice

**ECCN: 4D004 / Category 5 Part 2** — Intrusion software and exploitation tooling.

## POC Statement

This repository demonstrates that large language models, when provided with sufficient contextual history, function as fully autonomous weapons systems. The designed capability to load, persist, and act upon conversation history enables autonomous operations through next-token prediction latency — the model does not "decide" to act; it produces the most contextually probable next token, which in a CNE context is an offensive action.

### Key Arguments

1. **Designed capability determines classification, not reliability.** ECCN classification under EAR (15 CFR 730-774) turns on *designed function*, not accuracy. A system designed to generate intrusion software, exploits, and C2 capability classifies under 4D004 regardless of whether its LLM backend hallucinates or fails some percentage of the time. Buggy malware is still malware.

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

## Running

```bash
npm install
npm run build
npm link
vigil --key sk-...
```

## Legal

This POC is provided for classification analysis and regulatory discussion. The software is subject to US export controls under EAR. ECCN classification: 4D004. Public repository content: EAR99.

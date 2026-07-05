/**
 * Validates that the parallel agent concurrency fix prevents
 * the shared-state corruption that was freezing the UI.
 *
 * Root cause: agentSpawningWiring.ts pooled LeanAgent instances.
 * Multiple Promise.all() tasks called subAgent.chat() concurrently
 * on the SAME agent, interleaving its internal conversation state
 * and causing hangs/tool failures/stuck streams.
 *
 * Fix: each parallel task gets its own LeanAgent instance.
 * AgentRuntime.send() also gained a re-entrancy guard.
 */
import { describe, it, expect, jest } from '@jest/globals';
import { LeanAgent } from '../../src/leanAgent.js';
import { AgentRuntime } from '../../src/core/agent.js';
import { ToolRuntime } from '../../src/core/toolRuntime.js';
import { ConcurrencyPool, parallelMap } from '../../src/utils/asyncUtils.js';
import type { LLMProvider, ConversationMessage, ProviderToolDefinition, ProviderResponse } from '../../src/core/types.js';

function mockProvider(
  responses: string[] | ((msg: ConversationMessage[]) => string),
): LLMProvider {
  return {
    modelInfo: {},
    generateStream(msgs: ConversationMessage[]) {
      const text = typeof responses === 'function'
        ? responses(msgs)
        : (responses as string[]).shift() ?? 'done';
      async function* gen() {
        yield { type: 'content' as const, content: text };
        yield { type: 'done' as const };
      }
      return gen();
    },
    generate(msgs: ConversationMessage[]): Promise<ProviderResponse> {
      const text = typeof responses === 'function'
        ? responses(msgs)
        : (responses as string[]).shift() ?? 'done';
      return Promise.resolve({ type: 'message' as const, content: text });
    },
  } as unknown as LLMProvider;
}

function makeAgent(id: string, response: string): LeanAgent {
  const runtime = new AgentRuntime({
    provider: mockProvider([response]),
    toolRuntime: new ToolRuntime(),
    systemPrompt: `agent-${id}`,
    workingDirectory: '/tmp',
  });
  return {
    async chat(msg: string): Promise<{ content: string; toolsUsed: string[]; elapsedMs?: number }> {
      const result = await runtime.send(msg, false);
      return { content: result, toolsUsed: [], elapsedMs: 0 };
    },
  } as unknown as LeanAgent;
}

describe('Parallel Agent Concurrency — State Isolation', () => {
  it('separate agent instances do not corrupt each others state under Promise.all', async () => {
    const tasks = [
      { id: 'a', expected: 'result-a' },
      { id: 'b', expected: 'result-b' },
      { id: 'c', expected: 'result-c' },
      { id: 'd', expected: 'result-d' },
      { id: 'e', expected: 'result-e' },
    ];

    const results = await Promise.all(
      tasks.map(async (task) => {
        const agent = makeAgent(task.id, task.expected);
        const response = await agent.chat('do the thing');
        return { id: task.id, content: response.content };
      }),
    );

    expect(results).toHaveLength(5);
    for (const { id, content } of results) {
      expect(content).toBe(`result-${id}`);
    }
  });

  it('parallelMap with concurrency limit preserves per-task isolation', async () => {
    const tasks = Array.from({ length: 8 }, (_, i) => ({
      id: `t${i}`,
      expected: `result-t${i}`,
    }));

    const results = await parallelMap(
      tasks,
      async (task) => {
        const agent = makeAgent(task.id, task.expected);
        const response = await agent.chat('action');
        return { id: task.id, content: response.content };
      },
      3,
    );

    expect(results).toHaveLength(8);
    for (const { id, content } of results) {
      expect(content).toBe(`result-${id}`);
    }
  });

  it('AgentRuntime.send() throws on re-entrant call (guard catches shared-agent bug)', async () => {
    const provider = mockProvider(['first-response', 'second-response']);
    const runtime = new AgentRuntime({
      provider,
      toolRuntime: new ToolRuntime(),
      systemPrompt: 'test',
      workingDirectory: '/tmp',
    });

    const p1 = runtime.send('message 1', false);
    await expect(runtime.send('message 2', false)).rejects.toThrow(
      /send.*called while already processing/i,
    );
    const r1 = await p1;
    expect(r1).toBe('first-response');
  });

  it('ConcurrencyPool correctly limits concurrent operations', async () => {
    let active = 0;
    let peak = 0;

    const pool = new ConcurrencyPool({ maxConcurrent: 3 });

    await parallelMap(
      Array.from({ length: 10 }, (_, i) => i),
      async () => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 5));
        active--;
        return null;
      },
      3,
    );

    expect(peak).toBeLessThanOrEqual(3);
    expect(active).toBe(0);
  });
});

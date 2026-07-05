import { TodoCapabilityModule } from '../../../capabilities/todoCapability.js';
import type { ToolPlugin } from '../registry.js';

export function createTodoToolPlugin(): ToolPlugin {
  return {
    id: 'tool.todo',
    description: 'TodoWrite — Vigil-style task list for the agent.',
    targets: ['node', 'cloud', 'browser', 'universal'],
    create: () => new TodoCapabilityModule(),
  };
}

import { z } from 'zod';
import type { NodeConfig } from '../types.js';
import { config } from '../config.js';

const RegistrySchema = z.array(z.object({
  nodeId: z.string(),
  name: z.string().optional(),
  sqlitePath: z.string(),
  region: z.string().optional()
}));

export function loadNodeRegistry(): NodeConfig[] {
  if (!config.nodeRegistryJson) return [];
  const raw = JSON.parse(config.nodeRegistryJson);
  return RegistrySchema.parse(raw);
}

export function getNode(registry: NodeConfig[], nodeId: string): NodeConfig | undefined {
  return registry.find((n) => n.nodeId === nodeId);
}

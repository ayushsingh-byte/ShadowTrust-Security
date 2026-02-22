import type { FastifyInstance } from 'fastify';
import { loadNodeRegistry } from '../db/nodeRegistry.js';

export async function registerNodes(app: FastifyInstance) {
  app.get('/v1/nodes', async () => {
    const nodes = loadNodeRegistry();
    return { nodes };
  });
}

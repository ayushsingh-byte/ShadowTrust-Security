import type { FastifyInstance, FastifyRequest } from 'fastify';
import { verifySupabaseJwt } from '../auth/verifySupabaseJwt.js';
import type { AuthContext, Role } from '../types.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

function parseBearer(req: FastifyRequest): string | null {
  const header = req.headers['authorization'];
  if (!header) return null;
  const [kind, token] = header.split(' ');
  if (kind?.toLowerCase() !== 'bearer' || !token) return null;
  return token.trim();
}

export async function registerAuth(app: FastifyInstance) {
  app.addHook('preHandler', async (req, reply) => {
    if (req.url === '/health') return;
    const token = parseBearer(req);
    if (!token) {
      return reply.status(401).send({ error: 'missing_bearer_token' });
    }
    try {
      req.auth = await verifySupabaseJwt(token);
    } catch (e: any) {
      return reply.status(401).send({ error: 'invalid_token', detail: e?.message || 'JWT verification failed' });
    }
  });
}

export function requireRole(roles: Role[]) {
  return async (req: FastifyRequest, reply: any) => {
    const role = req.auth?.role;
    if (!role || !roles.includes(role)) {
      return reply.status(403).send({ error: 'forbidden' });
    }
  };
}

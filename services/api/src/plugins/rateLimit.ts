import type { FastifyInstance } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { config } from '../config.js';

export async function registerRateLimit(app: FastifyInstance) {
  await app.register(rateLimit, {
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindowMs,
    keyGenerator: (req) => {
      const userKey = req.auth?.userId ? `u:${req.auth.userId}` : null;
      return userKey || req.ip;
    }
  });
}

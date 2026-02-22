import type { FastifyInstance } from 'fastify';

export async function registerAudit(app: FastifyInstance) {
  app.addHook('onResponse', async (req, reply) => {
    const userId = req.auth?.userId || 'anonymous';
    const role = req.auth?.role || 'none';
    const nodeId = (req.query as any)?.nodeId || (req.params as any)?.nodeId;
    app.log.info({
      audit: true,
      userId,
      role,
      nodeId,
      method: req.method,
      url: req.url,
      statusCode: reply.statusCode
    });
  });
}

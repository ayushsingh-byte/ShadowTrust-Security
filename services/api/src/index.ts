import Fastify from 'fastify';
import { config } from './config.js';
import { registerHealth } from './routes/health.js';
import { registerNodes } from './routes/nodes.js';
import { registerAuth } from './plugins/auth.js';
import { registerRateLimit } from './plugins/rateLimit.js';
import { registerAudit } from './plugins/audit.js';

const app = Fastify({
  logger: true
});

await registerHealth(app);
await registerAuth(app);
await registerRateLimit(app);
await registerAudit(app);
await registerNodes(app);

await app.listen({ port: config.port, host: config.host });

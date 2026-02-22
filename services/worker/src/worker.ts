import * as dotenv from 'dotenv';
import pino from 'pino';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const log = pino();

const supabaseUrl = process.env.SUPABASE_URL || '';
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

if (!supabaseUrl || !serviceRoleKey) {
  log.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, serviceRoleKey, {
  auth: { persistSession: false }
});

async function tick() {
  // Placeholder: implement SQLite pull + enrichment + upsert into Supabase.
  // Design:
  // 1) query local SQLite for unsynced summaries (or build summaries from raw)
  // 2) enrich (geoip/fingerprint/risk)
  // 3) upsert to Supabase tables
  // 4) mark rows as synced in SQLite
  log.info({ sync: true }, 'Worker tick (not implemented yet)');

  // Example: write a heartbeat row (optional)
  await supabase.from('worker_heartbeats').upsert({
    id: 'worker',
    last_seen_at: new Date().toISOString()
  });
}

setInterval(() => {
  tick().catch((e) => log.error({ err: e }, 'Worker tick failed'));
}, Number(process.env.SYNC_INTERVAL_MS || 60_000));

await tick();

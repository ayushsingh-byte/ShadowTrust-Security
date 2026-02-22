import * as dotenv from 'dotenv';

dotenv.config();

export const config = {
  port: Number(process.env.PORT || 8000),
  host: process.env.HOST || '0.0.0.0',
  supabaseUrl: process.env.SUPABASE_URL || '',
  supabaseJwtAud: process.env.SUPABASE_JWT_AUD || 'authenticated',
  supabaseJwtIssuer: process.env.SUPABASE_JWT_ISS || '',
  supabaseJwksUrl: process.env.SUPABASE_JWKS_URL || '',
  nodeRegistryJson: process.env.NODE_REGISTRY_JSON || '',
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX || 120),
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000)
};

export function getSupabaseJwksUrl(): string {
  if (config.supabaseJwksUrl) return config.supabaseJwksUrl;
  if (!config.supabaseUrl) return '';
  return `${config.supabaseUrl.replace(/\/$/, '')}/auth/v1/.well-known/jwks.json`;
}

export function getSupabaseIssuer(): string {
  if (config.supabaseJwtIssuer) return config.supabaseJwtIssuer;
  if (!config.supabaseUrl) return '';
  return `${config.supabaseUrl.replace(/\/$/, '')}/auth/v1`;
}

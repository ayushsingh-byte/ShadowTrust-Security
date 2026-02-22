import { createRemoteJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { getSupabaseIssuer, getSupabaseJwksUrl, config } from '../config.js';
import type { AuthContext, Role } from '../types.js';

const JwtPayloadSchema = z.object({
  sub: z.string(),
  email: z.string().optional(),
  aud: z.union([z.string(), z.array(z.string())]).optional(),
  role: z.string().optional(),
  app_metadata: z.record(z.any()).optional(),
  user_metadata: z.record(z.any()).optional()
});

function coerceRole(roleRaw: unknown): Role {
  const role = String(roleRaw || '').toLowerCase();
  if (role === 'admin' || role === 'analyst' || role === 'viewer') return role;
  return 'viewer';
}

export async function verifySupabaseJwt(token: string): Promise<AuthContext> {
  const jwksUrl = getSupabaseJwksUrl();
  const issuer = getSupabaseIssuer();
  if (!jwksUrl || !issuer) {
    throw new Error('Supabase JWT verification not configured (missing SUPABASE_URL or SUPABASE_JWKS_URL/SUPABASE_JWT_ISS).');
  }

  const jwks = createRemoteJWKSet(new URL(jwksUrl));
  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: config.supabaseJwtAud
  });

  const parsed = JwtPayloadSchema.parse(payload);
  const role = coerceRole(parsed.app_metadata?.role ?? parsed.role);

  return {
    userId: parsed.sub,
    role,
    email: parsed.email
  };
}

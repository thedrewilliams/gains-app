// Gains Cloudflare Worker — Per-User Cloudflare Access Auth + D1 Sync

let cachedJwks = null;
let cachedJwksAt = 0;
const JWKS_TTL_MS = 10 * 60 * 1000;

function getD1Binding(env) {
  if (env.DB && typeof env.DB.prepare === 'function') return env.DB;
  for (const val of Object.values(env || {})) {
    if (val && typeof val.prepare === 'function' && typeof val.exec === 'function') {
      return val;
    }
  }
  return null;
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

async function ensureTable(db) {
  await db
    .prepare(
      'CREATE TABLE IF NOT EXISTS gains_state (id TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at TEXT NOT NULL)'
    )
    .run();
}

function base64UrlToUint8Array(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeJwtPart(part) {
  const bytes = base64UrlToUint8Array(part);
  return JSON.parse(new TextDecoder().decode(bytes));
}

function normalizeTeamDomain(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const trimmed = raw.trim().replace(/\/+$/, '');
  if (!trimmed) return '';
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return trimmed;
  if (trimmed.includes('.')) return `https://${trimmed}`;
  return `https://${trimmed}.cloudflareaccess.com`;
}

async function fetchCloudflareJwks(teamDomain) {
  const now = Date.now();
  if (cachedJwks && now - cachedJwksAt < JWKS_TTL_MS) {
    return cachedJwks;
  }
  const res = await fetch(`${teamDomain}/cdn-cgi/access/certs`, {
    cf: { cacheTtl: 600, cacheEverything: true }
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch Access certs (HTTP ${res.status})`);
  }
  const data = await res.json();
  if (!data || !Array.isArray(data.keys)) {
    throw new Error('Invalid Access JWKS response');
  }
  cachedJwks = data.keys;
  cachedJwksAt = now;
  return cachedJwks;
}

async function verifyAccessJwt(token, teamDomain, policyAud) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed Access JWT');

  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);
  const nowSec = Math.floor(Date.now() / 1000);

  if (payload.exp && nowSec >= payload.exp) {
    throw new Error('Access JWT expired');
  }
  if (teamDomain && payload.iss && payload.iss.replace(/\/+$/, '') !== teamDomain) {
    throw new Error('Access JWT issuer mismatch');
  }
  if (policyAud) {
    const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audList.includes(policyAud)) {
      throw new Error('Access JWT audience mismatch');
    }
  }

  const keys = await fetchCloudflareJwks(teamDomain);
  const jwk = keys.find((k) => k.kid === header.kid) || keys[0];
  if (!jwk) throw new Error('Matching Access signing key not found');

  const cryptoKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlToUint8Array(parts[2]);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, signingInput);
  if (!valid) throw new Error('Invalid Access JWT signature');

  return payload;
}

async function resolveUserIdentity(request, env) {
  const teamDomain = normalizeTeamDomain(env.TEAM_DOMAIN || env.CF_ACCESS_TEAM_DOMAIN || '');
  const policyAud = (env.POLICY_AUD || env.CF_ACCESS_AUD || '').trim();
  const requireAuth = String(env.REQUIRE_AUTH || '').toLowerCase() === 'true';
  const authConfigured = Boolean(teamDomain && policyAud);

  const jwtToken =
    request.headers.get('Cf-Access-Jwt-Assertion') ||
    request.headers.get('cf-access-jwt-assertion') ||
    '';
  const headerEmail = (
    request.headers.get('Cf-Access-Authenticated-User-Email') ||
    request.headers.get('cf-access-authenticated-user-email') ||
    ''
  )
    .trim()
    .toLowerCase();

  // Case 1: Full cryptographic JWT verification when TEAM_DOMAIN + POLICY_AUD are set
  if (authConfigured) {
    if (!jwtToken) {
      return {
        authenticated: false,
        verified: false,
        authConfigured: true,
        requireAuth,
        email: null,
        userId: requireAuth ? null : 'default'
      };
    }
    try {
      const claims = await verifyAccessJwt(jwtToken, teamDomain, policyAud);
      const email = String(claims.email || headerEmail || '').trim().toLowerCase();
      if (!email) {
        return {
          authenticated: false,
          verified: false,
          authConfigured: true,
          requireAuth,
          email: null,
          userId: null,
          error: 'No email claim in Access JWT'
        };
      }
      return {
        authenticated: true,
        verified: true,
        authConfigured: true,
        requireAuth,
        email,
        userId: email
      };
    } catch (err) {
      return {
        authenticated: false,
        verified: false,
        authConfigured: true,
        requireAuth: true,
        email: null,
        userId: null,
        error: err && err.message ? err.message : 'JWT verification failed'
      };
    }
  }

  // Case 2: Cloudflare Access is fronting the domain, TEAM_DOMAIN/POLICY_AUD not set yet
  if (jwtToken && headerEmail) {
    return {
      authenticated: true,
      verified: false,
      authConfigured: false,
      requireAuth,
      email: headerEmail,
      userId: headerEmail
    };
  }

  // Case 3: Unauthenticated (pre-Access setup or local dev)
  return {
    authenticated: false,
    verified: false,
    authConfigured: false,
    requireAuth,
    email: null,
    userId: requireAuth ? null : 'default'
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/me') {
      const identity = await resolveUserIdentity(request, env);
      return jsonResponse({
        ok: true,
        authenticated: identity.authenticated,
        verified: identity.verified,
        authConfigured: identity.authConfigured,
        email: identity.email,
        userId: identity.userId,
        loginUrl: '/cdn-cgi/access/login',
        logoutUrl: '/cdn-cgi/access/logout'
      });
    }

    if (url.pathname === '/api/sync') {
      const db = getD1Binding(env);
      if (!db) {
        return jsonResponse(
          { ok: false, error: 'D1 database binding not found in Worker settings.' },
          500
        );
      }

      const identity = await resolveUserIdentity(request, env);
      if (!identity.userId) {
        return jsonResponse(
          { ok: false, error: identity.error || 'Authentication required.' },
          401
        );
      }

      const rowId = identity.userId;
      const ownerEmail = String(env.OWNER_EMAIL || '').trim().toLowerCase();

      try {
        await ensureTable(db);

        if (request.method === 'GET') {
          let row = await db
            .prepare('SELECT state_json, updated_at FROM gains_state WHERE id = ?')
            .bind(rowId)
            .first();

          // One-time seamless migration: if Drew (OWNER_EMAIL) signs in for the first time,
          // migrate his existing 'default' workouts into his personal email row automatically.
          if (!row && identity.authenticated && ownerEmail && rowId === ownerEmail) {
            const legacyRow = await db
              .prepare('SELECT state_json, updated_at FROM gains_state WHERE id = ?')
              .bind('default')
              .first();
            if (legacyRow) {
              await db
                .prepare(
                  'INSERT INTO gains_state (id, state_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at'
                )
                .bind(rowId, legacyRow.state_json, legacyRow.updated_at)
                .run();
              row = legacyRow;
            }
          }

          if (!row) {
            return jsonResponse({
              ok: true,
              state: null,
              updatedAt: null,
              userId: rowId,
              authenticated: identity.authenticated
            });
          }

          let parsedState = null;
          try {
            parsedState = JSON.parse(row.state_json);
          } catch (_) {
            return jsonResponse({ ok: false, error: 'Corrupt state JSON in D1.' }, 500);
          }

          return jsonResponse({
            ok: true,
            state: parsedState,
            updatedAt: row.updated_at,
            userId: rowId,
            authenticated: identity.authenticated
          });
        }

        if (request.method === 'POST') {
          const body = await request.json();
          if (!body || !body.state || typeof body.state !== 'object') {
            return jsonResponse({ ok: false, error: 'Missing state object in request body.' }, 400);
          }

          const updatedAt = new Date().toISOString();
          const stateJson = JSON.stringify(body.state);

          await db
            .prepare(
              'INSERT INTO gains_state (id, state_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at'
            )
            .bind(rowId, stateJson, updatedAt)
            .run();

          return jsonResponse({
            ok: true,
            updatedAt,
            userId: rowId,
            authenticated: identity.authenticated
          });
        }

        return jsonResponse({ ok: false, error: 'Method not allowed.' }, 405);
      } catch (err) {
        return jsonResponse(
          { ok: false, error: err && err.message ? err.message : 'D1 query failed.' },
          500
        );
      }
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Static assets binding (ASSETS) is not configured.', { status: 500 });
  }
};

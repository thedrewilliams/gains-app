// Gains Cloudflare Worker — Native Zero-Cost Passkey (WebAuthn) + Google OAuth 2.0 + Per-User D1 Sync

const SESSION_COOKIE_NAME = 'gains_session';
const SESSION_TTL_SEC = 30 * 24 * 60 * 60; // 30 days
const CHALLENGE_TTL_MS = 5 * 60 * 1000;    // 5 minutes

function getD1Binding(env) {
  if (env.DB && typeof env.DB.prepare === 'function') return env.DB;
  for (const val of Object.values(env || {})) {
    if (val && typeof val.prepare === 'function' && typeof val.exec === 'function') {
      return val;
    }
  }
  return null;
}

function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
}

function randomBase64Url(byteLen = 32) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return uint8ToBase64Url(bytes);
}

function uint8ToBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToUint8(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const map = {};
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) map[k] = decodeURIComponent(v);
  });
  return map;
}

function buildSessionCookie(token, maxAgeSec, isHttps) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`
  ];
  if (isHttps) parts.push('Secure');
  return parts.join('; ');
}

// Convert ASN.1 DER ECDSA signature (WebAuthn format) to raw IEEE P1363 (r || s, 64 bytes) for WebCrypto
function derToP1363(derBytes, coordLen = 32) {
  if (derBytes.length === coordLen * 2) return derBytes;
  if (derBytes[0] !== 0x30) throw new Error('Invalid DER signature header');
  let offset = 2;
  if (derBytes[1] & 0x80) offset += derBytes[1] & 0x7f;

  if (derBytes[offset] !== 0x02) throw new Error('Invalid DER r marker');
  const rLen = derBytes[offset + 1];
  const rBytes = derBytes.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;

  if (derBytes[offset] !== 0x02) throw new Error('Invalid DER s marker');
  const sLen = derBytes[offset + 1];
  const sBytes = derBytes.slice(offset + 2, offset + 2 + sLen);

  const out = new Uint8Array(coordLen * 2);
  const copyInt = (src, destOffset) => {
    let start = 0;
    while (start < src.length - 1 && src[start] === 0x00) start++;
    const trimmed = src.slice(start);
    if (trimmed.length > coordLen) throw new Error('ECDSA coordinate overflow');
    out.set(trimmed, destOffset + (coordLen - trimmed.length));
  };
  copyInt(rBytes, 0);
  copyInt(sBytes, coordLen);
  return out;
}

async function ensureTables(db) {
  await db.batch([
    db.prepare(
      'CREATE TABLE IF NOT EXISTS gains_state (id TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at TEXT NOT NULL)'
    ),
    db.prepare(
      'CREATE TABLE IF NOT EXISTS gains_users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, created_at TEXT NOT NULL)'
    ),
    db.prepare(
      'CREATE TABLE IF NOT EXISTS gains_passkeys (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key_jwk TEXT NOT NULL, sign_count INTEGER DEFAULT 0, created_at TEXT NOT NULL)'
    ),
    db.prepare(
      'CREATE TABLE IF NOT EXISTS gains_challenges (challenge TEXT PRIMARY KEY, user_id TEXT, email TEXT, name TEXT, type TEXT NOT NULL, expires_at INTEGER NOT NULL)'
    ),
    db.prepare(
      'CREATE TABLE IF NOT EXISTS gains_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL)'
    )
  ]);
}

async function getAuthenticatedUser(request, db) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE_NAME];
  if (!token) return null;

  const now = Date.now();
  const row = await db
    .prepare(
      `SELECT u.id, u.email, u.name, s.expires_at
       FROM gains_sessions s
       JOIN gains_users u ON u.id = s.user_id
       WHERE s.token = ?`
    )
    .bind(token)
    .first();

  if (!row) return null;
  if (Number(row.expires_at) <= now) {
    await db.prepare('DELETE FROM gains_sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { id: row.id, email: row.email, name: row.name || '' };
}

async function createSessionForUser(db, userId) {
  const token = randomBase64Url(32);
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_SEC * 1000;
  await db
    .prepare('INSERT INTO gains_sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)')
    .bind(token, userId, expiresAt, new Date(now).toISOString())
    .run();
  return token;
}

async function findOrCreateUser(db, email, name = '') {
  const cleanEmail = String(email || '').trim().toLowerCase();
  if (!cleanEmail || !cleanEmail.includes('@')) {
    throw new Error('Please enter a valid email address.');
  }
  let user = await db
    .prepare('SELECT id, email, name FROM gains_users WHERE email = ?')
    .bind(cleanEmail)
    .first();
  if (user) {
    if (name && !user.name) {
      await db.prepare('UPDATE gains_users SET name = ? WHERE id = ?').bind(name.trim(), user.id).run();
      user.name = name.trim();
    }
    return user;
  }
  const id = `u_${randomBase64Url(12)}`;
  const displayName = (name || '').trim() || cleanEmail.split('@')[0];
  await db
    .prepare('INSERT INTO gains_users (id, email, name, created_at) VALUES (?, ?, ?, ?)')
    .bind(id, cleanEmail, displayName, new Date().toISOString())
    .run();
  return { id, email: cleanEmail, name: displayName };
}

async function storeChallenge(db, { challenge, userId = null, email = null, name = null, type }) {
  const now = Date.now();
  await db.prepare('DELETE FROM gains_challenges WHERE expires_at < ?').bind(now).run();
  await db
    .prepare(
      'INSERT INTO gains_challenges (challenge, user_id, email, name, type, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
    .bind(challenge, userId, email, name, type, now + CHALLENGE_TTL_MS)
    .run();
}

async function consumeChallenge(db, challenge, expectedType) {
  const row = await db
    .prepare('SELECT challenge, user_id, email, name, type, expires_at FROM gains_challenges WHERE challenge = ?')
    .bind(challenge)
    .first();
  if (!row) return null;
  await db.prepare('DELETE FROM gains_challenges WHERE challenge = ?').bind(challenge).run();
  if (row.type !== expectedType || Number(row.expires_at) < Date.now()) return null;
  return row;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isHttps = url.protocol === 'https:';
    const googleEnabled = Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
    const requireAuth = String(env.REQUIRE_AUTH || '').toLowerCase() === 'true';

    if (url.pathname.startsWith('/api/')) {
      const db = getD1Binding(env);
      if (!db) {
        return jsonResponse(
          { ok: false, error: 'D1 database binding not found in Worker settings.' },
          500
        );
      }

      try {
        await ensureTables(db);

        // -------------------------------------------------------------------
        // GET /api/me — Current authenticated user & available auth methods
        // -------------------------------------------------------------------
        if (url.pathname === '/api/me' && request.method === 'GET') {
          const user = await getAuthenticatedUser(request, db);
          return jsonResponse({
            ok: true,
            authenticated: Boolean(user),
            email: user ? user.email : null,
            name: user ? user.name : null,
            userId: user ? user.id : requireAuth ? null : 'default',
            passkeyEnabled: true,
            googleEnabled
          });
        }

        // -------------------------------------------------------------------
        // POST /api/auth/logout — Clear session in D1 and browser cookie
        // -------------------------------------------------------------------
        if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
          const cookies = parseCookies(request);
          if (cookies[SESSION_COOKIE_NAME]) {
            await db
              .prepare('DELETE FROM gains_sessions WHERE token = ?')
              .bind(cookies[SESSION_COOKIE_NAME])
              .run();
          }
          return jsonResponse(
            { ok: true },
            200,
            { 'Set-Cookie': buildSessionCookie('', 0, isHttps) }
          );
        }

        // -------------------------------------------------------------------
        // POST /api/auth/passkey/register/options — Start Passkey registration
        // -------------------------------------------------------------------
        if (url.pathname === '/api/auth/passkey/register/options' && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const authed = await getAuthenticatedUser(request, db);
          const email = authed ? authed.email : String(body.email || '').trim().toLowerCase();
          const name = authed ? authed.name : String(body.name || '').trim();

          if (!email || !email.includes('@')) {
            return jsonResponse({ ok: false, error: 'Enter a valid email address to register a Passkey.' }, 400);
          }

          // If not signed in and this email already has a passkey, require signing in first
          const existingUser = await db
            .prepare('SELECT id, email, name FROM gains_users WHERE email = ?')
            .bind(email)
            .first();
          let excludeCredentials = [];
          if (existingUser) {
            const creds = await db
              .prepare('SELECT credential_id FROM gains_passkeys WHERE user_id = ?')
              .bind(existingUser.id)
              .all();
            const existingCredList = (creds && creds.results) || [];
            if (existingCredList.length > 0 && (!authed || authed.id !== existingUser.id)) {
              return jsonResponse(
                { ok: false, error: 'An account with this email already has a Passkey. Tap Sign in with Passkey instead.' },
                409
              );
            }
            excludeCredentials = existingCredList.map((c) => ({
              type: 'public-key',
              id: c.credential_id
            }));
          }

          const challenge = randomBase64Url(32);
          const tempUserId = existingUser ? existingUser.id : `u_${randomBase64Url(12)}`;
          await storeChallenge(db, {
            challenge,
            userId: tempUserId,
            email,
            name: name || email.split('@')[0],
            type: 'passkey_register'
          });

          return jsonResponse({
            ok: true,
            options: {
              challenge,
              rp: { name: 'Gains', id: url.hostname },
              user: {
                id: uint8ToBase64Url(new TextEncoder().encode(tempUserId)),
                name: email,
                displayName: name || email.split('@')[0]
              },
              pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
              timeout: 60000,
              attestation: 'none',
              excludeCredentials,
              authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred'
              }
            }
          });
        }

        // -------------------------------------------------------------------
        // POST /api/auth/passkey/register/verify — Verify & save Passkey
        // -------------------------------------------------------------------
        if (url.pathname === '/api/auth/passkey/register/verify' && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          if (!body.id || !body.clientDataJSON || !body.publicKeySpki) {
            return jsonResponse({ ok: false, error: 'Missing Passkey registration payload.' }, 400);
          }

          const clientData = JSON.parse(new TextDecoder().decode(base64UrlToUint8(body.clientDataJSON)));
          if (clientData.type !== 'webauthn.create') {
            return jsonResponse({ ok: false, error: 'Invalid WebAuthn ceremony type.' }, 400);
          }
          if (clientData.origin !== url.origin) {
            return jsonResponse({ ok: false, error: 'Origin mismatch during Passkey registration.' }, 400);
          }

          const chal = await consumeChallenge(db, clientData.challenge, 'passkey_register');
          if (!chal) {
            return jsonResponse({ ok: false, error: 'Registration challenge expired. Please try again.' }, 400);
          }

          // Import SPKI P-256 public key and store as JWK
          const spkiBytes = base64UrlToUint8(body.publicKeySpki);
          const cryptoKey = await crypto.subtle.importKey(
            'spki',
            spkiBytes,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
          );
          const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);

          const user = await findOrCreateUser(db, chal.email, chal.name);
          await db
            .prepare(
              'INSERT INTO gains_passkeys (credential_id, user_id, public_key_jwk, sign_count, created_at) VALUES (?, ?, ?, 0, ?) ON CONFLICT(credential_id) DO UPDATE SET public_key_jwk = excluded.public_key_jwk'
            )
            .bind(body.id, user.id, JSON.stringify(jwk), new Date().toISOString())
            .run();

          const sessionToken = await createSessionForUser(db, user.id);
          return jsonResponse(
            { ok: true, user },
            200,
            { 'Set-Cookie': buildSessionCookie(sessionToken, SESSION_TTL_SEC, isHttps) }
          );
        }

        // -------------------------------------------------------------------
        // POST /api/auth/passkey/login/options — Start Passkey sign-in
        // -------------------------------------------------------------------
        if (url.pathname === '/api/auth/passkey/login/options' && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const email = String(body.email || '').trim().toLowerCase();
          let allowCredentials = [];

          if (email) {
            const user = await db
              .prepare('SELECT id FROM gains_users WHERE email = ?')
              .bind(email)
              .first();
            if (!user) {
              return jsonResponse(
                { ok: false, error: 'No account found for that email yet. Tap Create Passkey Account.' },
                404
              );
            }
            const creds = await db
              .prepare('SELECT credential_id FROM gains_passkeys WHERE user_id = ?')
              .bind(user.id)
              .all();
            allowCredentials = ((creds && creds.results) || []).map((c) => ({
              type: 'public-key',
              id: c.credential_id
            }));
            if (!allowCredentials.length) {
              return jsonResponse(
                { ok: false, error: 'No Passkey is registered for this email yet.' },
                404
              );
            }
          }

          const challenge = randomBase64Url(32);
          await storeChallenge(db, { challenge, email: email || null, type: 'passkey_login' });

          return jsonResponse({
            ok: true,
            options: {
              challenge,
              rpId: url.hostname,
              timeout: 60000,
              userVerification: 'preferred',
              allowCredentials
            }
          });
        }

        // -------------------------------------------------------------------
        // POST /api/auth/passkey/login/verify — Verify Passkey signature
        // -------------------------------------------------------------------
        if (url.pathname === '/api/auth/passkey/login/verify' && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          if (!body.id || !body.clientDataJSON || !body.authenticatorData || !body.signature) {
            return jsonResponse({ ok: false, error: 'Missing Passkey assertion payload.' }, 400);
          }

          const clientDataBytes = base64UrlToUint8(body.clientDataJSON);
          const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
          if (clientData.type !== 'webauthn.get') {
            return jsonResponse({ ok: false, error: 'Invalid WebAuthn assertion type.' }, 400);
          }
          if (clientData.origin !== url.origin) {
            return jsonResponse({ ok: false, error: 'Origin mismatch during Passkey sign-in.' }, 400);
          }

          const chal = await consumeChallenge(db, clientData.challenge, 'passkey_login');
          if (!chal) {
            return jsonResponse({ ok: false, error: 'Sign-in challenge expired. Please try again.' }, 400);
          }

          const credRow = await db
            .prepare(
              `SELECT p.credential_id, p.user_id, p.public_key_jwk, u.email, u.name
               FROM gains_passkeys p
               JOIN gains_users u ON u.id = p.user_id
               WHERE p.credential_id = ?`
            )
            .bind(body.id)
            .first();
          if (!credRow) {
            return jsonResponse({ ok: false, error: 'Passkey not recognized. Register a Passkey first.' }, 401);
          }

          const jwk = JSON.parse(credRow.public_key_jwk);
          const cryptoKey = await crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['verify']
          );

          const authDataBytes = base64UrlToUint8(body.authenticatorData);
          const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes));
          const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
          signedData.set(authDataBytes, 0);
          signedData.set(clientDataHash, authDataBytes.length);

          const rawSig = derToP1363(base64UrlToUint8(body.signature), 32);
          const valid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            cryptoKey,
            rawSig,
            signedData
          );
          if (!valid) {
            return jsonResponse({ ok: false, error: 'Passkey signature verification failed.' }, 401);
          }

          const sessionToken = await createSessionForUser(db, credRow.user_id);
          return jsonResponse(
            { ok: true, user: { id: credRow.user_id, email: credRow.email, name: credRow.name } },
            200,
            { 'Set-Cookie': buildSessionCookie(sessionToken, SESSION_TTL_SEC, isHttps) }
          );
        }

        // -------------------------------------------------------------------
        // GET /api/auth/google — Start free Google OAuth 2.0 flow
        // -------------------------------------------------------------------
        if (url.pathname === '/api/auth/google' && request.method === 'GET') {
          if (!googleEnabled) {
            return Response.redirect(`${url.origin}/?auth_error=google_not_configured`, 302);
          }
          const stateToken = randomBase64Url(24);
          await storeChallenge(db, { challenge: stateToken, type: 'google_oauth' });

          const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
          authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
          authUrl.searchParams.set('redirect_uri', `${url.origin}/api/auth/google/callback`);
          authUrl.searchParams.set('response_type', 'code');
          authUrl.searchParams.set('scope', 'openid email profile');
          authUrl.searchParams.set('state', stateToken);
          authUrl.searchParams.set('prompt', 'select_account');
          return Response.redirect(authUrl.toString(), 302);
        }

        // -------------------------------------------------------------------
        // GET /api/auth/google/callback — Complete Google OAuth 2.0 flow
        // -------------------------------------------------------------------
        if (url.pathname === '/api/auth/google/callback' && request.method === 'GET') {
          if (!googleEnabled) {
            return Response.redirect(`${url.origin}/?auth_error=google_not_configured`, 302);
          }
          const code = url.searchParams.get('code');
          const stateToken = url.searchParams.get('state');
          if (!code || !stateToken) {
            return Response.redirect(`${url.origin}/?auth_error=google_cancelled`, 302);
          }
          const chal = await consumeChallenge(db, stateToken, 'google_oauth');
          if (!chal) {
            return Response.redirect(`${url.origin}/?auth_error=google_expired`, 302);
          }

          const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              code,
              client_id: env.GOOGLE_CLIENT_ID,
              client_secret: env.GOOGLE_CLIENT_SECRET,
              redirect_uri: `${url.origin}/api/auth/google/callback`,
              grant_type: 'authorization_code'
            })
          });
          const tokenData = await tokenRes.json().catch(() => ({}));
          if (!tokenRes.ok || !tokenData.access_token) {
            return Response.redirect(`${url.origin}/?auth_error=google_token_failed`, 302);
          }

          const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
          });
          const profile = await userRes.json().catch(() => ({}));
          if (!userRes.ok || !profile.email) {
            return Response.redirect(`${url.origin}/?auth_error=google_profile_failed`, 302);
          }

          const user = await findOrCreateUser(db, profile.email, profile.given_name || profile.name || '');
          const sessionToken = await createSessionForUser(db, user.id);

          return new Response(null, {
            status: 302,
            headers: {
              Location: `${url.origin}/`,
              'Set-Cookie': buildSessionCookie(sessionToken, SESSION_TTL_SEC, isHttps)
            }
          });
        }

        // -------------------------------------------------------------------
        // GET / POST /api/sync — Isolated Per-User D1 Workout State Sync
        // -------------------------------------------------------------------
        if (url.pathname === '/api/sync') {
          const user = await getAuthenticatedUser(request, db);
          if (!user && requireAuth) {
            return jsonResponse({ ok: false, error: 'Please sign in to sync your workouts.' }, 401);
          }

          const rowId = user ? `user:${user.id}` : 'default';
          const ownerEmail = String(env.OWNER_EMAIL || '').trim().toLowerCase();

          if (request.method === 'GET') {
            let row = await db
              .prepare('SELECT state_json, updated_at FROM gains_state WHERE id = ?')
              .bind(rowId)
              .first();

            // One-time automatic migration: when Drew (OWNER_EMAIL) signs in for the first time,
            // carry over his existing 'default' workouts into his private user row automatically.
            if (!row && user && ownerEmail && user.email === ownerEmail) {
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
                authenticated: Boolean(user)
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
              authenticated: Boolean(user)
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
              authenticated: Boolean(user)
            });
          }

          return jsonResponse({ ok: false, error: 'Method not allowed.' }, 405);
        }

        return jsonResponse({ ok: false, error: 'API route not found.' }, 404);
      } catch (err) {
        return jsonResponse(
          { ok: false, error: err && err.message ? err.message : 'Server error.' },
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

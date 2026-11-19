const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json; charset=utf-8',
};

async function ensureTable(db) {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS app_sync_state (
        user_key TEXT PRIMARY KEY,
        state_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    )
    .run();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/sync') {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: CORS_HEADERS });
      }

      if (!env.DB) {
        return new Response(
          JSON.stringify({ ok: false, error: 'D1 binding "DB" is not configured' }),
          { status: 500, headers: CORS_HEADERS }
        );
      }

      const userKey = 'default_user';

      try {
        await ensureTable(env.DB);

        if (request.method === 'GET') {
          const row = await env.DB
            .prepare('SELECT state_json, updated_at FROM app_sync_state WHERE user_key = ?')
            .bind(userKey)
            .first();

          if (!row || !row.state_json) {
            return new Response(
              JSON.stringify({ ok: true, state: null, updatedAt: null }),
              { status: 200, headers: CORS_HEADERS }
            );
          }

          return new Response(
            JSON.stringify({
              ok: true,
              state: JSON.parse(row.state_json),
              updatedAt: row.updated_at,
            }),
            { status: 200, headers: CORS_HEADERS }
          );
        }

        if (request.method === 'POST') {
          const body = await request.json();
          const incomingState = body && body.state ? body.state : null;
          if (!incomingState || typeof incomingState !== 'object') {
            return new Response(
              JSON.stringify({ ok: false, error: 'Invalid payload: missing state object' }),
              { status: 400, headers: CORS_HEADERS }
            );
          }

          const nowIso = new Date().toISOString();
          incomingState.updatedAt = nowIso;

          await env.DB
            .prepare(
              `INSERT INTO app_sync_state (user_key, state_json, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(user_key) DO UPDATE SET
                 state_json = excluded.state_json,
                 updated_at = excluded.updated_at`
            )
            .bind(userKey, JSON.stringify(incomingState), nowIso)
            .run();

          return new Response(
            JSON.stringify({ ok: true, updatedAt: nowIso }),
            { status: 200, headers: CORS_HEADERS }
          );
        }

        return new Response(
          JSON.stringify({ ok: false, error: 'Method not allowed' }),
          { status: 405, headers: CORS_HEADERS }
        );
      } catch (err) {
        return new Response(
          JSON.stringify({ ok: false, error: err?.message || 'D1 error' }),
          { status: 500, headers: CORS_HEADERS }
        );
      }
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Not found', { status: 404 });
  },
};

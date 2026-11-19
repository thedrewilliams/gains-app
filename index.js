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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/sync') {
      const db = getD1Binding(env);
      if (!db) {
        return jsonResponse(
          { ok: false, error: 'D1 database binding not found in Worker settings.' },
          500
        );
      }

      try {
        await ensureTable(db);

        if (request.method === 'GET') {
          const row = await db
            .prepare('SELECT state_json, updated_at FROM gains_state WHERE id = ?')
            .bind('default')
            .first();

          if (!row) {
            return jsonResponse({ ok: true, state: null, updatedAt: null });
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
            updatedAt: row.updated_at
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
            .bind('default', stateJson, updatedAt)
            .run();

          return jsonResponse({ ok: true, updatedAt });
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

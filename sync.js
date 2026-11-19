export async function onRequest(context) {
  const { request, env } = context;
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json; charset=utf-8',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (!env.DB) {
    return new Response(
      JSON.stringify({ ok: false, error: 'Missing D1 binding "DB" in Cloudflare Pages settings' }),
      { status: 500, headers: corsHeaders }
    );
  }

  const userKey = 'default_user';

  try {
    if (request.method === 'GET') {
      const row = await env.DB
        .prepare('SELECT state_json, updated_at FROM app_sync_state WHERE user_key = ?')
        .bind(userKey)
        .first();

      if (!row || !row.state_json) {
        return new Response(
          JSON.stringify({ ok: true, state: null, updatedAt: null }),
          { status: 200, headers: corsHeaders }
        );
      }

      return new Response(
        JSON.stringify({
          ok: true,
          state: JSON.parse(row.state_json),
          updatedAt: row.updated_at,
        }),
        { status: 200, headers: corsHeaders }
      );
    }

    if (request.method === 'POST') {
      const body = await request.json();
      const incomingState = body && body.state ? body.state : null;
      if (!incomingState || typeof incomingState !== 'object') {
        return new Response(
          JSON.stringify({ ok: false, error: 'Invalid payload: missing state object' }),
          { status: 400, headers: corsHeaders }
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
        { status: 200, headers: corsHeaders }
      );
    }

    return new Response(
      JSON.stringify({ ok: false, error: 'Method not allowed' }),
      { status: 405, headers: corsHeaders }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: err?.message || 'D1 query failed' }),
      { status: 500, headers: corsHeaders }
    );
  }
}

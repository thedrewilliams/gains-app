export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Handle /api/sync requests against Cloudflare D1
    if (url.pathname === "/api/sync") {
      if (request.method === "GET") {
        const row = await env.DB.prepare(
          "SELECT payload, updated_at FROM app_state WHERE id = 'default'"
        ).first();

        return Response.json({
          ok: true,
          state: row ? JSON.parse(row.payload) : null,
          updatedAt: row ? row.updated_at : null
        });
      }

      if (request.method === "POST") {
        const body = await request.json();
        const now = new Date().toISOString();

        await env.DB.prepare(
          `INSERT INTO app_state (id, payload, updated_at)
           VALUES ('default', ?1, ?2)
           ON CONFLICT(id) DO UPDATE SET
             payload = excluded.payload,
             updated_at = excluded.updated_at`
        )
          .bind(JSON.stringify(body.state), now)
          .run();

        return Response.json({ ok: true, updatedAt: now });
      }

      return new Response("Method not allowed", { status: 405 });
    }

    // Serve index.html and static assets for all other routes
    return env.ASSETS.fetch(request);
  }
};

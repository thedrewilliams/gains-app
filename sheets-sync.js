exports.handler = async (event) => {
  const scriptUrl = process.env.GOOGLE_SCRIPT_URL;
  const secretToken = process.env.GOOGLE_SCRIPT_TOKEN;

  if (!scriptUrl || !secretToken) {
    return {
      statusCode: 500,
      body: JSON.stringify({ ok: false, error: 'Missing Netlify environment variables' })
    };
  }

  try {
    if (event.httpMethod === 'GET') {
      const res = await fetch(`${scriptUrl}?token=${encodeURIComponent(secretToken)}`);
      const data = await res.json();
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      };
    }

    if (event.httpMethod === 'POST') {
      const incoming = JSON.parse(event.body || '{}');
      const res = await fetch(scriptUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: secretToken,
          state: incoming.state,
          sessionRows: incoming.sessionRows
        })
      });
      const data = await res.json();
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      };
    }

    return { statusCode: 405, body: 'Method Not Allowed' };
  } catch (err) {
    return {
      statusCode: 502,
      body: JSON.stringify({ ok: false, error: err.message })
    };
  }
};
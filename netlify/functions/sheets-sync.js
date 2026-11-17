exports.handler = async (event) => {
  const WEBAPP_URL = process.env.GOOGLE_SHEETS_WEBAPP_URL || process.env.SHEETS_WEBAPP_URL;

  if (!WEBAPP_URL) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: false, error: 'Missing GOOGLE_SHEETS_WEBAPP_URL in Netlify' })
    };
  }

  try {
    const isPost = event.httpMethod === 'POST';
    const response = await fetch(WEBAPP_URL, {
      method: isPost ? 'POST' : 'GET',
      headers: isPost ? { 'Content-Type': 'text/plain;charset=utf-8' } : {},
      body: isPost ? event.body : undefined,
      redirect: 'follow'
    });

    const rawText = await response.text();
    let data;
    try {
      data = JSON.parse(rawText);
    } catch (parseErr) {
      const isHtml = rawText.trim().startsWith('<!DOCTYPE') || rawText.trim().startsWith('<html');
      return {
        statusCode: 502,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ok: false,
          error: isHtml
            ? 'Apps Script returned HTML (Check "Who has access: Anyone" & /exec URL)'
            : `Invalid JSON from Apps Script: ${rawText.slice(0, 80)}`
        })
      };
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: false, error: err.message || 'Netlify function error' })
    };
  }
};

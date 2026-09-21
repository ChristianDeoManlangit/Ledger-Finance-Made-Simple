// Exchanges a one-time Google OAuth authorization code (from the client's
// popup sign-in) for an access token and a refresh token. The access
// token goes back to the browser; the refresh token, which never expires
// on its own, stays here in an httpOnly cookie the browser JS can't read.
// This is the piece that fixes the "signed out every hour" problem: the
// browser never has to do a silent iframe reauth (which gets blocked)
// because it can always ask this endpoint's sibling, /api/google/refresh,
// for a new access token using that stored refresh token instead.
//
// Required environment variables (set in Vercel project settings):
//   GOOGLE_CLIENT_ID     - same client ID already used in index.html
//   GOOGLE_CLIENT_SECRET - from the same OAuth Client in Google Cloud Console

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "method-not-allowed" });
    return;
  }

  try {
    const { code } = req.body || {};
    if (!code) {
      res.status(400).json({ error: "missing-code" });
      return;
    }

    // Google Identity Services' popup code flow uses the calling page's
    // own origin as the redirect_uri (see index.html's ensureCodeClient),
    // so the exchange has to send back that same value, or Google
    // rejects it with a redirect_uri_mismatch error.
    const origin = `https://${req.headers.host}`;

    const params = new URLSearchParams({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: origin,
      grant_type: "authorization_code",
    });

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const data = await tokenRes.json();

    if (!tokenRes.ok) {
      res.status(400).json({ error: data.error || "exchange-failed", detail: data.error_description });
      return;
    }

    // A refresh token is only ever included on the FIRST exchange for a
    // given consent grant. If the person disconnects and reconnects, or
    // re-consents, Google sends a new one and this simply overwrites the
    // cookie. Scoped to /api/google so it's never sent anywhere else.
    if (data.refresh_token) {
      res.setHeader(
        "Set-Cookie",
        `g_rt=${encodeURIComponent(data.refresh_token)}; HttpOnly; Secure; SameSite=Strict; Path=/api/google; Max-Age=15552000`
      );
    }

    res.status(200).json({ access_token: data.access_token, expires_in: data.expires_in });
  } catch (e) {
    res.status(500).json({ error: "server-error" });
  }
}

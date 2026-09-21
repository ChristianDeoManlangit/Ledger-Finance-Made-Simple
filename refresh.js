// Uses the refresh token cookie (set by /api/google/exchange) to mint a
// fresh access token, no popup, no iframe, no browser sign-in flow at
// all. The client calls this on every page load and again on a timer
// shortly before each access token expires (see scheduleTokenRefresh in
// index.html's GoogleSync module), so a signed-in person should never
// need to click "sign in" again unless they explicitly disconnect or
// revoke access from their Google account.

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const match = header.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

export default async function handler(req, res) {
  try {
    const refreshToken = getCookie(req, "g_rt");
    if (!refreshToken) {
      res.status(401).json({ error: "no-refresh-token" });
      return;
    }

    const params = new URLSearchParams({
      refresh_token: refreshToken,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      grant_type: "refresh_token",
    });

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const data = await tokenRes.json();

    if (!tokenRes.ok) {
      // The refresh token itself is dead (revoked from the person's
      // Google account, or expired from months of inactivity). Clear it
      // so the app doesn't keep retrying a token that will never work,
      // and falls back to asking for a normal sign-in instead.
      res.setHeader(
        "Set-Cookie",
        "g_rt=; HttpOnly; Secure; SameSite=Strict; Path=/api/google; Max-Age=0"
      );
      res.status(401).json({ error: data.error || "refresh-failed" });
      return;
    }

    res.status(200).json({ access_token: data.access_token, expires_in: data.expires_in });
  } catch (e) {
    res.status(500).json({ error: "server-error" });
  }
}

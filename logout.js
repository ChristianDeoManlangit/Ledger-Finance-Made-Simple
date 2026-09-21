// Clears the refresh token cookie when the person disconnects Google
// sync from within the app. Doesn't revoke the token with Google itself
// (index.html already calls google.accounts.oauth2.revoke for that) -
// this just makes sure nothing is left sitting in the browser afterwards.

export default async function handler(req, res) {
  res.setHeader(
    "Set-Cookie",
    "g_rt=; HttpOnly; Secure; SameSite=Strict; Path=/api/google; Max-Age=0"
  );
  res.status(200).json({ ok: true });
}

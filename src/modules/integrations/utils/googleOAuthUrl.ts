// Google OAuth is a top-level redirect, not an XHR. Send the browser to the
// backend's authenticated start route (the bearer token rides on the proxied
// session for same-origin dev; in prod this becomes a full OAuth handshake).
export function googleConnectUrl(): string {
  const base = import.meta.env.VITE_API_BASE_URL || '/api';
  return `${base}/auth/google`;
}

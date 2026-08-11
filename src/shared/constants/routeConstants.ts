/**
 * Route paths that more than one layer has to agree on.
 *
 * Most paths live in exactly one place — the route table — and belong nowhere else.
 * These are the exceptions: paths the app has to navigate to from outside the
 * router, where a second literal could silently drift from the route that defines
 * it and leave the redirect pointing at a 404.
 */

/**
 * The forced password-change screen.
 *
 * Referenced by three layers that must not disagree: the route table declares it,
 * ProtectedRoute redirects a user who owes a password change to it, and baseQuery
 * redirects there on a 403 PASSWORD_CHANGE_REQUIRED from the API.
 */
export const CHANGE_PASSWORD_PATH = '/change-password';

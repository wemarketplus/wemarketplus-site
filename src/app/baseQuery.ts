import {
  fetchBaseQuery,
  type BaseQueryFn,
  type FetchArgs,
  type FetchBaseQueryError,
} from '@reduxjs/toolkit/query';
import { Mutex } from 'async-mutex';
import { logout, patchUser, setCredentials } from '@/modules/auth/store/authSlice';
import { CHANGE_PASSWORD_PATH } from '@/shared/constants/routeConstants';
import type { ApiEnvelope } from '@/shared/types';
import type { LoginResponse } from '@/modules/auth/types/authTypes';
import type { RootState } from './store';

// Single mutex serializes 401 recovery so a thundering-herd of concurrent
// requests doesn't fire N refresh calls (or N logouts) at once. The first
// 401 acquires the lock and refreshes; everyone else waits, then replays
// against the freshly-stored access token.
const mutex = new Mutex();

const rawBaseQuery = fetchBaseQuery({
  baseUrl: import.meta.env.VITE_API_BASE_URL || '/api',
  prepareHeaders: (headers, { getState }) => {
    const token = (getState() as RootState).auth?.token;
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return headers;
  },
});

function forceLogout(api: Parameters<typeof rawBaseQuery>[1]): void {
  api.dispatch(logout());
  // Hard redirect so PersistGate + RTK Query caches both reset cleanly.
  if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
    window.location.href = '/login';
  }
}

// Both spellings of the billing screen (see router.tsx).
const BILLING_PATHS = ['/billing', '/subscription-status'];

// Thrown by the backend's PasswordChangeGuard. 403 alone is not enough to act on
// — it is also every ordinary role denial — so this matches the specific code.
const PASSWORD_CHANGE_REQUIRED = 'PASSWORD_CHANGE_REQUIRED';

// Thrown by the backend's TierGuard for a feature above the tenant's tier, as
// opposed to SUBSCRIPTION_REQUIRED for having no subscription at all.
const UPGRADE_REQUIRED = 'UPGRADE_REQUIRED';

function isPasswordChangeRequired(error: FetchBaseQueryError): boolean {
  if (error.status !== 403) return false;
  const data = error.data as { error?: unknown } | undefined;
  return data?.error === PASSWORD_CHANGE_REQUIRED;
}

/**
 * Recovery for a client that does not yet know it is locked out.
 *
 * ProtectedRoute already redirects on the `mustChangePassword` flag, so in the
 * normal flow this never fires. It covers the case the flag cannot: an admin
 * resetting someone's password mid-session. That user's stored profile still says
 * false, and without this every screen would quietly fill with failed requests.
 * Flipping the flag makes the router's own gate do the rest.
 */
function requirePasswordChange(api: Parameters<typeof rawBaseQuery>[1]): void {
  api.dispatch(patchUser({ mustChangePassword: true }));
  if (
    typeof window !== 'undefined' &&
    window.location.pathname !== CHANGE_PASSWORD_PATH
  ) {
    window.location.assign(CHANGE_PASSWORD_PATH);
  }
}

/**
 * Distinguishes the two very different reasons the API answers 402.
 *
 * SUBSCRIPTION_REQUIRED (subscription.guard.ts) means the tenant has no live
 * subscription at all — every feature endpoint is gated, so bouncing to the plan
 * picker is the only useful move.
 *
 * UPGRADE_REQUIRED (tier.guard.ts) is not that. The tenant IS subscribed; this
 * one feature sits above their tier. The backend documents the code as existing
 * precisely "so the frontend can" show an in-place upgrade prompt, and screens
 * like ManageCustomRoles already compute a `needsUpgrade` flag to do exactly
 * that — but that code was unreachable, because this interceptor hard-redirected
 * the whole window to /billing before the component could render. That is the
 * "Settings tabs bounce me back to Billing" bug: opening a tier-gated tab fired
 * its query, the 402 landed, and the page navigated away mid-tab-switch.
 *
 * So only the first kind redirects; the second is returned to the caller.
 */
function isSubscriptionRequired(error: FetchBaseQueryError): boolean {
  if (error.status !== 402) return false;
  const data = error.data as { error?: unknown } | undefined;
  // Default to redirecting when the body carries no code: a 402 we cannot
  // classify is likelier to be the whole-account gate than a per-feature one.
  return data?.error !== UPGRADE_REQUIRED;
}

// Hard redirect to the plan picker, mirroring forceLogout's style; the pathname
// guard prevents a redirect loop while the billing screen itself loads.
function redirectToBilling(): void {
  if (
    typeof window !== 'undefined' &&
    !BILLING_PATHS.includes(window.location.pathname)
  ) {
    window.location.assign('/billing');
  }
}

export const baseQueryWithReauth: BaseQueryFn<
  string | FetchArgs,
  unknown,
  FetchBaseQueryError
> = async (args, api, extraOptions) => {
  await mutex.waitForUnlock();
  let result = await rawBaseQuery(args, api, extraOptions);

  // Only a whole-account subscription gate redirects. A per-feature
  // UPGRADE_REQUIRED falls through so the calling screen can render its own
  // upgrade prompt in place — see isSubscriptionRequired.
  if (result.error && isSubscriptionRequired(result.error)) {
    redirectToBilling();
    return result;
  }

  // Before the 401 branch: this is a 403, so refreshing the token would not help
  // and the request must not be replayed.
  if (result.error && isPasswordChangeRequired(result.error)) {
    requirePasswordChange(api);
    return result;
  }

  if (result.error?.status !== 401) {
    return result;
  }

  // Don't try to refresh the refresh call itself — that just loops.
  const url = typeof args === 'string' ? args : args.url;
  if (url.includes('/auth/refresh') || url.includes('/auth/login')) {
    forceLogout(api);
    return result;
  }

  if (!mutex.isLocked()) {
    const release = await mutex.acquire();
    try {
      const refreshToken = (api.getState() as RootState).auth?.refreshToken;
      if (!refreshToken) {
        forceLogout(api);
        return result;
      }

      const refreshResult = await rawBaseQuery(
        { url: '/auth/refresh', method: 'POST', body: { refreshToken } },
        api,
        extraOptions,
      );

      const payload = (refreshResult.data as ApiEnvelope<LoginResponse> | undefined)?.data;
      if (payload?.accessToken) {
        api.dispatch(
          setCredentials({
            token: payload.accessToken,
            refreshToken: payload.refreshToken ?? refreshToken,
            user: payload.user,
          }),
        );
        // Replay the original request with the new access token.
        result = await rawBaseQuery(args, api, extraOptions);
      } else {
        forceLogout(api);
      }
    } finally {
      release();
    }
  } else {
    // Another request is already refreshing; wait, then replay.
    await mutex.waitForUnlock();
    result = await rawBaseQuery(args, api, extraOptions);
  }

  return result;
};

import {
  fetchBaseQuery,
  type BaseQueryFn,
  type FetchArgs,
  type FetchBaseQueryError,
} from '@reduxjs/toolkit/query';
import { Mutex } from 'async-mutex';
import { logout, setCredentials } from '@/modules/auth/store/authSlice';
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

// 402 SUBSCRIPTION_REQUIRED: the tenant has no live subscription, so every
// feature endpoint is gated until they pick a plan. Hard redirect to the
// plan picker, mirroring forceLogout's style; the pathname guard prevents a
// redirect loop while the billing screen itself loads.
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

  if (result.error?.status === 402) {
    redirectToBilling();
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

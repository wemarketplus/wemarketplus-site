import {
  fetchBaseQuery,
  type BaseQueryFn,
  type FetchArgs,
  type FetchBaseQueryError,
} from '@reduxjs/toolkit/query';
import { Mutex } from 'async-mutex';
import { logout } from '@/modules/auth/store/authSlice';
import type { RootState } from './store';

// Single mutex prevents a thundering-herd of 401 handlers from racing.
// Today's wemarketplus-backend has no /auth/refresh endpoint, so on 401 we just
// log out and bounce to /login. The mutex is still useful: concurrent in-flight
// requests should all observe the same logout once, not stomp each other.
// TODO: when the backend ships a refresh-token endpoint, switch this to the
// classic acquire-mutex / call /auth/refresh / replay-original-request flow
// (see ISS/servia-orgadmin/src/app/baseQuery.ts for the pattern).
const mutex = new Mutex();

const rawBaseQuery = fetchBaseQuery({
  baseUrl: import.meta.env.VITE_API_BASE_URL || '/api',
  prepareHeaders: (headers, { getState }) => {
    const token = (getState() as RootState).auth?.token;
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return headers;
  },
});

export const baseQueryWithReauth: BaseQueryFn<
  string | FetchArgs,
  unknown,
  FetchBaseQueryError
> = async (args, api, extraOptions) => {
  await mutex.waitForUnlock();
  const result = await rawBaseQuery(args, api, extraOptions);

  if (result.error?.status === 401) {
    if (!mutex.isLocked()) {
      const release = await mutex.acquire();
      try {
        api.dispatch(logout());
        // Hard redirect so PersistGate + RTK Query caches both reset cleanly.
        if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
      } finally {
        release();
      }
    } else {
      // Another request is already handling the logout; just wait it out.
      await mutex.waitForUnlock();
    }
  }

  return result;
};

import { useEffect } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { useMeQuery } from '../api/authApi';
import { setCredentials } from '../store/authSlice';

// Keeps the persisted auth user fresh. When authenticated it re-fetches
// /auth/me on load and merges the latest profile into the auth slice — most
// importantly the `entitlements` array, which drives the product switcher. This
// is why an already-logged-in user (whose persisted session predates
// entitlements) or one who was just granted a second product sees the switcher
// appear without having to log out and back in. Renders nothing.
export function ProfileSync() {
  const dispatch = useAppDispatch();
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);
  const { data } = useMeQuery(undefined, { skip: !isAuthenticated });

  useEffect(() => {
    if (data) {
      dispatch(setCredentials({ user: data }));
    }
  }, [data, dispatch]);

  return null;
}

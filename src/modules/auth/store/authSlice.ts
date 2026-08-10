import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { AuthenticatedUser, AuthState } from '../types/authTypes';

const initialState: AuthState = {
  token: null,
  refreshToken: null,
  user: null,
  isAuthenticated: false,
};

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setCredentials(
      state,
      action: PayloadAction<{
        token?: string | null;
        refreshToken?: string | null;
        user?: AuthenticatedUser | null;
      }>,
    ) {
      if (action.payload.token !== undefined) state.token = action.payload.token;
      if (action.payload.refreshToken !== undefined) {
        state.refreshToken = action.payload.refreshToken;
      }
      if (action.payload.user !== undefined) state.user = action.payload.user;
      state.isAuthenticated = Boolean(state.token);
    },
    /**
     * Merges freshly saved profile fields into the cached user.
     *
     * Deliberately a MERGE, and deliberately not `setCredentials({ user })`.
     * PATCH /users/me returns a plain UserResponseDto with no tenant context, so
     * assigning it wholesale would drop `product`, `tier`, `organizationName`,
     * `subscriptionStatus` and `entitlements` — the fields the sidebar, the
     * dashboard router and the product switcher all gate on. Someone renaming
     * themselves would find the product switcher had vanished.
     *
     * A no-op when there is no user: a profile save cannot create a session.
     */
    patchUser(state, action: PayloadAction<Partial<AuthenticatedUser>>) {
      if (!state.user) return;
      state.user = { ...state.user, ...action.payload };
    },
    logout(state) {
      state.token = null;
      state.refreshToken = null;
      state.user = null;
      state.isAuthenticated = false;
    },
  },
});

export const { setCredentials, patchUser, logout } = authSlice.actions;
export default authSlice.reducer;

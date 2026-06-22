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
    logout(state) {
      state.token = null;
      state.refreshToken = null;
      state.user = null;
      state.isAuthenticated = false;
    },
  },
});

export const { setCredentials, logout } = authSlice.actions;
export default authSlice.reducer;

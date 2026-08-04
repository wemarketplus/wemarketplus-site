import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { Product } from '@/shared/types';
import type { Role } from '@/shared/rbac';

// Which dashboard the user is currently viewing when they are entitled to more
// than one product. `null` means "not yet chosen" — a selector resolves the
// effective product (falling back to the user's primary entitlement), so this
// value can safely lag behind the entitlement list. Persisted (see store.ts
// whitelist) so the selection survives a page refresh.
export interface AccessState {
  activeProduct: Product | null;
  /**
   * The field persona a management user is previewing, or null for "yourself".
   *
   * This is a RENDER-ONLY value. `usePermission` refuses to honour it unless the
   * real role may switch and the requested role is a field persona, and no request
   * is affected by it — the JWT still carries the real role. Persisted alongside
   * activeProduct so a preview survives a refresh (and is cleared on logout).
   */
  viewAsRole: Role | null;
}

const initialState: AccessState = {
  activeProduct: null,
  viewAsRole: null,
};

const accessSlice = createSlice({
  name: 'access',
  initialState,
  reducers: {
    setActiveProduct(state, action: PayloadAction<Product>) {
      state.activeProduct = action.payload;
    },
    clearActiveProduct(state) {
      state.activeProduct = null;
    },
    setViewAsRole(state, action: PayloadAction<Role | null>) {
      state.viewAsRole = action.payload;
    },
    clearViewAsRole(state) {
      state.viewAsRole = null;
    },
  },
  extraReducers: (builder) => {
    // Reset the switcher when the session ends so the next login starts from its
    // own primary product rather than inheriting the previous user's choice.
    builder.addCase('auth/logout', (state) => {
      state.activeProduct = null;
      // A preview must never outlive the session that started it — otherwise the
      // next user could land in a scoped view they did not choose.
      state.viewAsRole = null;
    });
  },
});

export const {
  setActiveProduct,
  clearActiveProduct,
  setViewAsRole,
  clearViewAsRole,
} = accessSlice.actions;
export default accessSlice.reducer;

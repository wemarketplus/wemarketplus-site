import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { Product } from '@/shared/types';

/**
 * Which dashboard the user is currently viewing when they are entitled to more
 * than one product. `null` means "not yet chosen" — a selector resolves the
 * effective product (falling back to the user's primary entitlement), so this
 * value can safely lag behind the entitlement list. Persisted (see store.ts
 * whitelist) so the selection survives a page refresh.
 *
 * This slice used to also hold `viewAsRole`, the persona a management user was
 * previewing. That is gone with the switcher: the "Viewing as" row reports the
 * signed-in role and offers no others. Removing the FIELD, not just the control,
 * is the point — it was persisted, so leaving it would have let a stale value keep
 * narrowing someone's navigation with nothing left to clear it. A stale key in
 * already-persisted storage is simply ignored now: nothing reads it.
 */
export interface AccessState {
  activeProduct: Product | null;
}

const initialState: AccessState = {
  activeProduct: null,
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
  },
  extraReducers: (builder) => {
    // Reset the dashboard selection when the session ends, so the next login
    // starts from its own primary product rather than inheriting the previous
    // user's choice.
    builder.addCase('auth/logout', (state) => {
      state.activeProduct = null;
    });
  },
});

export const { setActiveProduct, clearActiveProduct } = accessSlice.actions;
export default accessSlice.reducer;

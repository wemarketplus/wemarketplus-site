import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { Product } from '@/shared/types';

// Which dashboard the user is currently viewing when they are entitled to more
// than one product. `null` means "not yet chosen" — a selector resolves the
// effective product (falling back to the user's primary entitlement), so this
// value can safely lag behind the entitlement list. Persisted (see store.ts
// whitelist) so the selection survives a page refresh.
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
    // Reset the switcher when the session ends so the next login starts from its
    // own primary product rather than inheriting the previous user's choice.
    builder.addCase('auth/logout', (state) => {
      state.activeProduct = null;
    });
  },
});

export const { setActiveProduct, clearActiveProduct } = accessSlice.actions;
export default accessSlice.reducer;

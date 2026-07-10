import { createSlice } from '@reduxjs/toolkit';

// UI-only slice placeholder; server state lives in featureFlagsApi. Kept so the
// module follows the store-registration convention of its siblings.
const featureFlagsSlice = createSlice({
  name: 'featureFlags',
  initialState: { _placeholder: true } as { _placeholder: true },
  reducers: {},
});

export default featureFlagsSlice.reducer;

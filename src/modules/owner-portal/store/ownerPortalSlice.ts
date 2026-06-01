import { createSlice } from '@reduxjs/toolkit';
import type { OwnerPortalUiState } from '../types/ownerPortalTypes';

const initialState: OwnerPortalUiState = { _placeholder: true };

const ownerPortalSlice = createSlice({
  name: 'ownerPortal',
  initialState,
  reducers: {},
});

export default ownerPortalSlice.reducer;

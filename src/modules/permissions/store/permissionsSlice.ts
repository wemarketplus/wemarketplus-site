import { createSlice } from '@reduxjs/toolkit';
import type { PermissionsUiState } from '../types/permissionsTypes';

const initialState: PermissionsUiState = { _placeholder: true };

const permissionsSlice = createSlice({
  name: 'permissions',
  initialState,
  reducers: {},
});

export default permissionsSlice.reducer;

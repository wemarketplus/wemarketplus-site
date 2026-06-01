import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ClOperationsUiState } from '../types/clOperationsTypes';

const initialState: ClOperationsUiState = { view: 'inventory' };

const clOperationsSlice = createSlice({
  name: 'clOperations',
  initialState,
  reducers: {
    setOperationsView(
      state,
      action: PayloadAction<ClOperationsUiState['view']>,
    ) {
      state.view = action.payload;
    },
  },
});

export const { setOperationsView } = clOperationsSlice.actions;
export default clOperationsSlice.reducer;

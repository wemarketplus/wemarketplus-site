import { createSlice } from '@reduxjs/toolkit';
import type { ClToursUiState } from '../types/clToursTypes';

const initialState: ClToursUiState = { _placeholder: true };

const clToursSlice = createSlice({
  name: 'clTours',
  initialState,
  reducers: {},
});

export default clToursSlice.reducer;

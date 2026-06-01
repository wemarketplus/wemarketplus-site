import { createSlice } from '@reduxjs/toolkit';
import type { ClinicalUiState } from '../types/clinicalTypes';

const initialState: ClinicalUiState = { _placeholder: true };

const clinicalSlice = createSlice({
  name: 'clinical',
  initialState,
  reducers: {},
});

export default clinicalSlice.reducer;

import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ClOutreachUiState } from '../types/clOutreachTypes';

const initialState: ClOutreachUiState = { view: 'checkin' };

const clOutreachSlice = createSlice({
  name: 'clOutreach',
  initialState,
  reducers: {
    setOutreachView(state, action: PayloadAction<ClOutreachUiState['view']>) {
      state.view = action.payload;
    },
  },
});

export const { setOutreachView } = clOutreachSlice.actions;
export default clOutreachSlice.reducer;

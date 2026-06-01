import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { AppNotification } from '@/shared/types';
import type { NotificationsUiState } from '../types/notificationsTypes';

const initialState: NotificationsUiState = {
  drawerOpen: false,
  filter: 'all',
};

const notificationsSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    openDrawer(state) {
      state.drawerOpen = true;
    },
    closeDrawer(state) {
      state.drawerOpen = false;
    },
    toggleDrawer(state) {
      state.drawerOpen = !state.drawerOpen;
    },
    setFilter(
      state,
      action: PayloadAction<'all' | 'unread' | AppNotification['category']>,
    ) {
      state.filter = action.payload;
    },
  },
});

export const { openDrawer, closeDrawer, toggleDrawer, setFilter } =
  notificationsSlice.actions;
export default notificationsSlice.reducer;

import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { Role } from '@/shared/rbac';
import type { UsersUiState } from '../types/usersTypes';

const initialState: UsersUiState = {
  search: '',
  selectedRole: 'all',
};

const usersSlice = createSlice({
  name: 'users',
  initialState,
  reducers: {
    setSearch(state, action: PayloadAction<string>) {
      state.search = action.payload;
    },
    setSelectedRole(state, action: PayloadAction<Role | 'all'>) {
      state.selectedRole = action.payload;
    },
    resetUsersUi() {
      return initialState;
    },
  },
});

export const { setSearch, setSelectedRole, resetUsersUi } = usersSlice.actions;
export default usersSlice.reducer;

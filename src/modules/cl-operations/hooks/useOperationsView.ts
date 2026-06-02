import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { setOperationsView } from '../store/clOperationsSlice';
import type { ClOperationsUiState } from '../types/clOperationsTypes';

export function useOperationsView() {
  const dispatch = useAppDispatch();
  const view = useAppSelector((s) => s.clOperations.view);

  function changeView(next: ClOperationsUiState['view']) {
    dispatch(setOperationsView(next));
  }

  return { view, changeView };
}

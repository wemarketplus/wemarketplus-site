import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { setOutreachView } from '../store/clOutreachSlice';
import type { ClOutreachUiState } from '../types/clOutreachTypes';

export function useOutreachView() {
  const dispatch = useAppDispatch();
  const view = useAppSelector((s) => s.clOutreach.view);
  const setView = (v: ClOutreachUiState['view']) => dispatch(setOutreachView(v));
  return { view, setView };
}

import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { setFinancialView } from '../store/clFinancialSlice';
import type { ClFinancialUiState } from '../types/clFinancialTypes';

export function useFinancialView() {
  const dispatch = useAppDispatch();
  const view = useAppSelector((s) => s.clFinancial.view);
  const setView = (v: ClFinancialUiState['view']) => dispatch(setFinancialView(v));
  return { view, setView };
}

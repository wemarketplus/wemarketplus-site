import { useLocation, useNavigate } from 'react-router-dom';
import type { ClFinancialUiState } from '../types/clFinancialTypes';

type View = ClFinancialUiState['view'];

const PATH_BY_VIEW: Record<View, string> = {
  ledger: '/financial/ledger',
  leakage: '/financial/leakage',
  concessions: '/financial/concessions',
  competitors: '/financial/competitors',
  loc: '/financial/loc',
};

const SEGMENT_TO_VIEW: Record<string, View> = {
  ledger: 'ledger',
  leakage: 'leakage',
  concessions: 'concessions',
  competitors: 'competitors',
  loc: 'loc',
};

// The financial sub-views are URL-addressable, so the active view is derived
// from the path and switching it navigates — each sidebar item lands on its
// own view.
export function useFinancialView() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const segment = pathname.split('/').pop() ?? '';
  const view: View = SEGMENT_TO_VIEW[segment] ?? 'ledger';

  const setView = (v: View) => navigate(PATH_BY_VIEW[v]);

  return { view, setView };
}

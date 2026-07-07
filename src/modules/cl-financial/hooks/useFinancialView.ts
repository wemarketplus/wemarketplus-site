import { useLocation, useNavigate } from 'react-router-dom';
import type { ClFinancialUiState } from '../types/clFinancialTypes';

type View = ClFinancialUiState['view'];

const PATH_BY_VIEW: Record<View, string> = {
  ledger: '/financial/ledger',
  leakage: '/financial/leakage',
  concessions: '/financial/concessions',
};

const VIEWS: readonly View[] = ['ledger', 'leakage', 'concessions'];

// The financial sub-views are URL-addressable, so the active view is derived
// from the path and switching it navigates — /financial/ledger and
// /financial/leakage (both in the sidebar) each land on their own view.
export function useFinancialView() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const segment = pathname.split('/').pop() as View | undefined;
  const view: View = segment && VIEWS.includes(segment) ? segment : 'ledger';

  const setView = (v: View) => navigate(PATH_BY_VIEW[v]);

  return { view, setView };
}

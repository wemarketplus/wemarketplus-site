import { useLocation, useNavigate } from 'react-router-dom';
import type { ClOperationsUiState } from '../types/clOperationsTypes';

type View = ClOperationsUiState['view'];

const PATH_BY_VIEW: Record<View, string> = {
  communities: '/operations/communities',
  inventory: '/operations/inventory',
  'make-ready': '/operations/make-ready',
  maintenance: '/operations/maintenance',
  housekeeping: '/operations/housekeeping',
  'unit-status': '/operations/unit-status',
  'maintenance-view': '/operations/maintenance-view',
};

const VIEWS: readonly View[] = [
  'communities',
  'inventory',
  'make-ready',
  'maintenance',
  'housekeeping',
  'unit-status',
  'maintenance-view',
];

// Each operations sub-page is its own route, so the active view comes from the
// URL and changing it navigates — every sidebar link lands on its own view
// instead of all four showing the same one.
export function useOperationsView() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const segment = pathname.split('/').pop() as View | undefined;
  const view: View = segment && VIEWS.includes(segment) ? segment : 'inventory';

  const changeView = (next: View) => navigate(PATH_BY_VIEW[next]);

  return { view, changeView };
}

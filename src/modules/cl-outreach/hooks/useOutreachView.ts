import { useLocation, useNavigate } from 'react-router-dom';
import type { ClOutreachUiState } from '../types/clOutreachTypes';

type View = ClOutreachUiState['view'];

const PATH_BY_VIEW: Record<View, string> = {
  checkin: '/outreach/checkin',
  mileage: '/outreach/mileage',
  log: '/outreach/log',
};

// The three sidebar links (/outreach/checkin, /mileage, /log) are distinct
// routes, so the active view is derived from the URL — not local state — and
// changing it navigates. This keeps each nav item on its own page instead of
// all three showing the same view.
export function useOutreachView() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const segment = pathname.split('/').pop();
  const view: View =
    segment === 'mileage' || segment === 'log' ? segment : 'checkin';

  const setView = (v: View) => navigate(PATH_BY_VIEW[v]);

  return { view, setView };
}

import { useLocation, useNavigate } from 'react-router-dom';
import type { ClOutreachUiState } from '../types/clOutreachTypes';

type View = ClOutreachUiState['view'];

const PATH_BY_VIEW: Record<View, string> = {
  checkin: '/outreach/checkin',
  log: '/outreach/log',
};

// The two sidebar links (/outreach/checkin, /outreach/log) are distinct routes,
// so the active view is derived from the URL — not local state — and changing it
// navigates. This keeps each nav item on its own page instead of both showing the
// same view. `/outreach/mileage` was a third view here and is now a redirect to
// the shared mileage screen (see router.tsx).
export function useOutreachView() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const segment = pathname.split('/').pop();
  const view: View = segment === 'log' ? 'log' : 'checkin';

  const setView = (v: View) => navigate(PATH_BY_VIEW[v]);

  return { view, setView };
}

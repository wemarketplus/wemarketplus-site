export interface DashboardStatCard {
  id: string;
  label: string;
  value: string;
  hint?: string;
  tone?: 'primary' | 'azure' | 'amber' | 'success' | 'warning' | 'destructive';
}

export interface DashboardActivityItem {
  id: string;
  title: string;
  detail: string;
  // ISO date — formatted at render time via formatRelative.
  occurredAt: string;
}

// UI state — reserved for future toggles (date range, segment).
export interface DashboardUiState {
  _placeholder: true;
}

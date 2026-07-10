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

// Live tenant KPI summary — wemarketplus-backend/src/dashboard
// (DashboardSummaryDto from GET /dashboard/summary). Tenant-scoped aggregate
// assembled from prospects/tasks/revenue/notifications/audit.
export interface DashboardSummary {
  product: string;
  prospects: {
    total: number;
    byStage: Record<string, number>;
  };
  tasks: {
    open: number;
  };
  invoices: {
    overdue: number;
    outstanding: number;
  };
  notifications: {
    unread: number;
  };
  recentActivity: DashboardSummaryActivity[];
}

export interface DashboardSummaryActivity {
  id: string;
  action: string;
  resource: string | null;
  resourceId: string | null;
  // ISO date.
  createdAt: string;
}

// UI state — reserved for future toggles (date range, segment).
export interface DashboardUiState {
  _placeholder: true;
}

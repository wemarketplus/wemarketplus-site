import type { ComponentType } from 'react';

export interface DashboardStatCard {
  id: string;
  label: string;
  value: string;
  hint?: string;
  tone?: 'primary' | 'azure' | 'amber' | 'success' | 'warning' | 'destructive';
  // Lucide glyph shown in the tinted chip at the tile's top-right, per the
  // reference design. Optional so a tile can render without one.
  icon?: ComponentType<{ className?: string }>;
}

export interface DashboardActivityItem {
  id: string;
  title: string;
  detail: string;
  /** Display name of the user who did it; "System" for system-written rows. */
  actorName: string;
  actorEmail: string | null;
  // ISO date — rendered as both an absolute date/time and a relative age.
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
  actorName: string;
  actorEmail: string | null;
  // ISO date.
  createdAt: string;
}

// UI state — reserved for future toggles (date range, segment).
export interface DashboardUiState {
  _placeholder: true;
}

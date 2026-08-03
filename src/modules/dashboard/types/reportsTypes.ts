import type { ISODateString } from '@/shared/types';

// Backend reports summary shapes — wemarketplus-backend/src/reports
// (ReportSummaryDto). Grant-CRM shaped (companies/applications/grant revenue).
export interface ReportTotals {
  companies: number;
  applications: number;
  pendingCompliance: number;
}

export interface ReportRevenue {
  totalAwarded: number;
  totalFees: number;
  totalCollected: number;
  outstanding: number;
}

export interface ReportRecentActivity {
  action: string;
  resource: string | null;
  createdAt: ISODateString;
}

export interface ReportSummary {
  totals: ReportTotals;
  revenue: ReportRevenue;
  applicationsByStatus: Record<string, number>;
  recentActivity: ReportRecentActivity[];
}

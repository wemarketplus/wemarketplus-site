import type { ISODateString } from '@/shared/types';

// Backend reports summary shapes — wemarketplus-backend/src/reports
// (ReportSummaryDto). Grant-CRM shaped (wibs/companies/applications/grant revenue).
export interface ReportTotals {
  wibs: number;
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

export interface ReportTopWib {
  wibName: string;
  state: string | null;
  callPriorityScore: number;
  status: string;
}

export interface ReportSummary {
  totals: ReportTotals;
  revenue: ReportRevenue;
  applicationsByStatus: Record<string, number>;
  recentActivity: ReportRecentActivity[];
  topWibs: ReportTopWib[];
}

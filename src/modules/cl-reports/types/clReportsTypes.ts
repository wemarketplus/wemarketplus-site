export interface ReportDefinition {
  id: string;
  title: string;
  description: string;
  // `sales` is the Sales Marketer's group (leads by source, tour conversion) and
  // the only category available on every tier — the other four come from the
  // Gold+ operations bundle. See ClReportsService's per-report gating.
  category: 'sales' | 'occupancy' | 'revenue' | 'operations' | 'compliance';
  lastRunAt?: string;
}

// Live computed report from wemarketplus-backend cl/reports.
export interface ClReportMetric {
  category: string;
  metric: string;
  value: string;
  tone: 'g' | 'y' | 'r' | 'b' | 'neutral';
}

export interface ClReportResult {
  id: string;
  title: string;
  metrics: ClReportMetric[];
  unavailable?: boolean;
  note?: string;
}

export interface ClReportsUiState {
  _placeholder: true;
}

// --- Component prop types ---

export interface ReportCardProps {
  report: ReportDefinition;
}

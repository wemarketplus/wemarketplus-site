export interface ReportDefinition {
  id: string;
  title: string;
  description: string;
  category: 'occupancy' | 'revenue' | 'operations' | 'compliance';
  lastRunAt?: string;
}

export interface ClReportsUiState {
  _placeholder: true;
}

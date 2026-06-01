export interface FinancialMonth {
  month: string;
  revenue: number;
  concessions: number;
  leakage: number;
}

export interface ClFinancialUiState {
  view: 'ledger' | 'leakage' | 'concessions';
}

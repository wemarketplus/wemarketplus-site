export interface FinancialMonth {
  month: string;
  revenue: number;
  concessions: number;
  leakage: number;
}

export interface ClFinancialUiState {
  view: 'ledger' | 'leakage' | 'concessions' | 'competitors' | 'loc';
}

// --- Component prop types ---

export interface FinancialTableProps {
  months: readonly FinancialMonth[];
  highlight: 'revenue' | 'concessions' | 'leakage';
}

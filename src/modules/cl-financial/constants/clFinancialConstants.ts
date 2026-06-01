import type {
  ClFinancialUiState,
  FinancialMonth,
} from '../types/clFinancialTypes';

export const FINANCIAL_VIEWS: ReadonlyArray<{
  value: ClFinancialUiState['view'];
  label: string;
}> = [
  { value: 'ledger', label: 'Ledger' },
  { value: 'leakage', label: 'Leakage' },
  { value: 'concessions', label: 'Concessions' },
];

export const FINANCIAL_HISTORY: readonly FinancialMonth[] = [
  { month: 'Jan', revenue: 318000, concessions: 12000, leakage: 4200 },
  { month: 'Feb', revenue: 331000, concessions: 14500, leakage: 3800 },
  { month: 'Mar', revenue: 345000, concessions: 9800, leakage: 5100 },
  { month: 'Apr', revenue: 361000, concessions: 11200, leakage: 4400 },
  { month: 'May', revenue: 378000, concessions: 10800, leakage: 3950 },
];

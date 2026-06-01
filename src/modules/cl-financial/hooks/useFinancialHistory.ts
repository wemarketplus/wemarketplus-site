import { FINANCIAL_HISTORY } from '../constants/clFinancialConstants';

export function useFinancialHistory() {
  return { months: FINANCIAL_HISTORY, isUsingFixture: true };
}

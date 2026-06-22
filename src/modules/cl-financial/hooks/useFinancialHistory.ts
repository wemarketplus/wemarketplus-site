import { useMemo } from 'react';
import { FINANCIAL_HISTORY } from '../constants/clFinancialConstants';
import { useListClConcessionsQuery, useListClRevenueQuery } from '../api/clFinancialApi';
import type { FinancialMonth } from '../types/clFinancialTypes';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// Aggregate raw revenue entries + concessions into the monthly summary the UI
// renders. Leakage is approximated as budget shortfall (budget - actual, when
// the entry under-ran its budget).
export function useFinancialHistory() {
  const revenue = useListClRevenueQuery();
  const concessions = useListClConcessionsQuery();

  const live = Boolean(
    (revenue.data && revenue.data.data.length > 0) ||
      (concessions.data && concessions.data.data.length > 0),
  );

  const months = useMemo<readonly FinancialMonth[]>(() => {
    if (!live) return FINANCIAL_HISTORY;

    const byMonth = new Map<string, FinancialMonth>();
    const bucket = (key: string): FinancialMonth => {
      let m = byMonth.get(key);
      if (!m) {
        m = { month: key, revenue: 0, concessions: 0, leakage: 0 };
        byMonth.set(key, m);
      }
      return m;
    };

    for (const r of revenue.data?.data ?? []) {
      const month = MONTHS[new Date(r.entryDate).getMonth()] ?? r.entryDate.slice(0, 7);
      const m = bucket(month);
      m.revenue += Number(r.amount) || 0;
      if (r.budgetAmount != null) {
        m.leakage += Math.max(0, Number(r.budgetAmount) - Number(r.amount));
      }
    }
    for (const c of concessions.data?.data ?? []) {
      const month = MONTHS[new Date(c.createdAt).getMonth()] ?? c.createdAt.slice(0, 7);
      bucket(month).concessions += Number(c.valueAmount) || 0;
    }

    return Array.from(byMonth.values());
  }, [live, revenue.data, concessions.data]);

  return { months, isUsingFixture: !live };
}

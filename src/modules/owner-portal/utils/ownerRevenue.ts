import type { OwnerRevenueMonth } from '../types/ownerPortalTypes';

// Peak MRR across the window — used to scale the revenue bar chart.
export function getMaxMrr(months: readonly OwnerRevenueMonth[]): number {
  return Math.max(...months.map((m) => m.mrr));
}

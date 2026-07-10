import { useMemo } from 'react';
import { useGetOwnerMetricsQuery, useListOwnerCustomersQuery } from '../api/ownerPortalApi';
import type { OwnerKPI } from '../types/ownerPortalTypes';

// Dashboard KPI strip, sourced from the endpoints the backend actually exposes
// today (/owner/metrics + /owner/customers). MRR/ARR/churn are intentionally
// omitted until a billing-analytics endpoint ships — we surface only metrics we
// can compute truthfully rather than fabricated financials.
export function useOwnerKpis(): {
  kpis: readonly OwnerKPI[];
  isLoading: boolean;
  isError: boolean;
} {
  const metrics = useGetOwnerMetricsQuery();
  const customers = useListOwnerCustomersQuery();

  const kpis = useMemo<OwnerKPI[]>(() => {
    const list: OwnerKPI[] = [];
    if (customers.data) {
      list.push({
        id: 'customers',
        label: 'Active customers',
        value: String(customers.data.total),
      });
    }
    if (metrics.data) {
      list.push({
        id: 'pipeline',
        label: 'Pipeline records',
        value: String(metrics.data.totalPipeline),
      });
    }
    return list;
  }, [metrics.data, customers.data]);

  return {
    kpis,
    isLoading: metrics.isLoading || customers.isLoading,
    isError: metrics.isError || customers.isError,
  };
}

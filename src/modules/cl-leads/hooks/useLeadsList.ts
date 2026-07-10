import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useListClLeadsQuery } from '../api/leadsApi';
import { mapClLead, resolveLeads } from '../utils/leadsUtils';

// Live (mapped from /cl/leads) for the logged-in tenant, or an empty state
// when the tenant has no leads. Session-added leads + status overrides still
// layer on top so the Add Lead modal and inline status changes keep working.
export function useLeadsList() {
  const status = useAppSelector((s) => s.clLeads.statusFilter);
  const added = useAppSelector((s) => s.clLeads.added);
  const overrides = useAppSelector((s) => s.clLeads.statusOverrides);
  const { data } = useListClLeadsQuery();

  const base = useMemo(() => data?.data.map(mapClLead) ?? [], [data]);

  const leads = useMemo(
    () => resolveLeads(base, added, overrides, status),
    [base, added, overrides, status],
  );

  return {
    leads,
    total: (data?.total ?? 0) + added.length,
    isUsingFixture: false,
  };
}

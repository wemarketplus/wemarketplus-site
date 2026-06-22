import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { LEADS_FIXTURE } from '@/shared/fixtures';
import { useListClLeadsQuery } from '../api/leadsApi';
import { mapClLead, resolveLeads } from '../utils/leadsUtils';

// Live (mapped from /cl/leads) when the tenant has leads, otherwise the
// fixture. Session-added leads + status overrides still layer on top so the
// Add Lead modal and inline status changes keep working.
export function useLeadsList() {
  const status = useAppSelector((s) => s.clLeads.statusFilter);
  const added = useAppSelector((s) => s.clLeads.added);
  const overrides = useAppSelector((s) => s.clLeads.statusOverrides);
  const { data } = useListClLeadsQuery();

  const base = useMemo(
    () => (data && data.data.length > 0 ? data.data.map(mapClLead) : LEADS_FIXTURE),
    [data],
  );

  const leads = useMemo(
    () => resolveLeads(base, added, overrides, status),
    [base, added, overrides, status],
  );

  return {
    leads,
    total: (data?.total ?? LEADS_FIXTURE.length) + added.length,
    isUsingFixture: !data || data.data.length === 0,
  };
}

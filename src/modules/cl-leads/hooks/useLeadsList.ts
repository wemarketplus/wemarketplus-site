import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { LEADS_FIXTURE } from '@/shared/fixtures';
import { resolveLeads } from '../utils/leadsUtils';

// Exposes the live (fixture + session-added, status-overridden) lead list.
export function useLeadsList() {
  const status = useAppSelector((s) => s.clLeads.statusFilter);
  const added = useAppSelector((s) => s.clLeads.added);
  const overrides = useAppSelector((s) => s.clLeads.statusOverrides);

  const leads = useMemo(
    () => resolveLeads(LEADS_FIXTURE, added, overrides, status),
    [added, overrides, status],
  );

  return {
    leads,
    total: LEADS_FIXTURE.length + added.length,
    isUsingFixture: added.length === 0,
  };
}

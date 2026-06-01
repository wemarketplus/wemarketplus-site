import type { Lead, LeadStatus } from '@/shared/types';

export function filterLeads(
  leads: readonly Lead[],
  status: LeadStatus | 'all',
): readonly Lead[] {
  if (status === 'all') return leads;
  return leads.filter((l) => l.status === status);
}

// Merges added leads (prepended) with the fixture, applies per-id status
// overrides, then filters. Pure — keeps the hook orchestration-only.
export function resolveLeads(
  fixture: readonly Lead[],
  added: readonly Lead[],
  overrides: Record<string, LeadStatus>,
  filter: LeadStatus | 'all',
): readonly Lead[] {
  const all = [...added, ...fixture].map((l) =>
    overrides[l.id] ? { ...l, status: overrides[l.id] } : l,
  );
  return filterLeads(all, filter);
}

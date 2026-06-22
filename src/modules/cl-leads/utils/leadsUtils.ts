import { LeadStatus as LeadStatusEnum, CareLevel } from '@/shared/types';
import type { Lead, LeadStatus } from '@/shared/types';
import type { ClLeadRecord } from '../types/clLeadApiTypes';
import type { ClLeadStage } from '../constants/clLeadApiConstants';

// Backend LeadStage has more stages than the UI's LeadStatus; collapse them.
function stageToStatus(stage: ClLeadStage): LeadStatus {
  switch (stage) {
    case 'tour_scheduled':
    case 'toured':
      return LeadStatusEnum.TourScheduled;
    case 'proposal_sent':
      return LeadStatusEnum.Proposal;
    case 'deposit_paid':
      return LeadStatusEnum.FollowUp;
    case 'moved_in':
      return LeadStatusEnum.MoveIn;
    case 'lost':
    case 'inactive':
      return LeadStatusEnum.Lost;
    case 'contacted':
    case 'inquiry':
    default:
      return LeadStatusEnum.Inquiry;
  }
}

export function mapClLead(r: ClLeadRecord): Lead {
  return {
    id: r.id,
    name: [r.firstName, r.lastName].filter(Boolean).join(' '),
    careType: (r.careLevel ?? CareLevel.IL) as Lead['careType'],
    status: stageToStatus(r.stage),
    urgency: r.urgency as Lead['urgency'],
    source: r.source ?? '',
    followUpDate: r.followUpDate ?? r.updatedAt,
    phone: r.phone ?? '',
    email: r.email ?? '',
    notes: r.notes ?? undefined,
  };
}

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

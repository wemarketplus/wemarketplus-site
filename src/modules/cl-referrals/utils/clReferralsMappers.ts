import type { ClReferralSourceRecord } from '../types/clReferralsApiTypes';
import type { SeniorLivingReferral } from '../types/clReferralsTypes';

// Map a backend referral source onto the UI's SeniorLivingReferral. The backend
// `type` is free-form; bucket it into the UI's source categories. Pure mappers —
// kept in utils/ so the hook stays orchestration-only.
function mapSource(type: string | null): SeniorLivingReferral['source'] {
  const t = (type ?? '').toLowerCase();
  if (t.includes('physician') || t.includes('doctor')) return 'physician';
  if (t.includes('hospital')) return 'hospital';
  if (t.includes('family')) return 'family';
  if (t.includes('web') || t.includes('online')) return 'web';
  return 'community';
}

export function toSeniorLivingReferral(r: ClReferralSourceRecord): SeniorLivingReferral {
  return {
    id: r.id,
    name: r.name,
    organization: r.organization ?? '',
    email: r.email ?? '',
    phone: r.phone ?? '',
    source: mapSource(r.type),
    rating: 3,
    notes: r.notes ?? undefined,
  };
}

import { ReferralSourceStatus as Status } from '@/shared/types';
import type { ReferralSource, ReferralSourceStatus } from '@/shared/types';
import {
  ReferralAccountStatus,
  type ReferralSourceRecord,
} from '../types/referralsTypes';

// The backend referral_sources row is now the full account record, so the health
// pill and priority come from REAL columns (`status`, `priorityTier`) instead of
// being inferred from the AI score. aiScore still drives the 1–5 trust display,
// which has no backend equivalent.
function accountStatusToHealth(
  status: ReferralAccountStatus,
): ReferralSourceStatus {
  switch (status) {
    case ReferralAccountStatus.ActiveReferrer:
      return Status.Green;
    case ReferralAccountStatus.Prospect:
      return Status.Building;
    case ReferralAccountStatus.Dormant:
    default:
      return Status.Red;
  }
}

function scoreToTrust(score: number): ReferralSource['trustLevel'] {
  return Math.min(5, Math.max(1, Math.round(score / 2))) as ReferralSource['trustLevel'];
}

export function mapReferralSource(r: ReferralSourceRecord): ReferralSource {
  return {
    id: r.id,
    fullName: r.contactName ?? r.name,
    title: '',
    organization: r.name,
    workPhone: r.phone ?? '',
    email: r.email ?? '',
    sourceType: r.type,
    status: accountStatusToHealth(r.status),
    trustLevel: scoreToTrust(r.aiScore),
    priorityLevel: r.priorityTier,
    lastContactDate: r.updatedAt,
    assignedMarketer: r.accountOwnerId ?? '',
    territoryArea: [r.city, r.state].filter(Boolean).join(', ') || undefined,
    // Real rollup, maintained by the backend on lead conversion.
    referralCount: r.referralVolume,
    acceptsGifts: false,
  };
}

export function filterReferrals(
  items: readonly ReferralSource[],
  args: { search: string; status: ReferralSourceStatus | 'all' },
): readonly ReferralSource[] {
  const needle = args.search.trim().toLowerCase();
  return items.filter((r) => {
    if (args.status !== 'all' && r.status !== args.status) return false;
    if (!needle) return true;
    return (
      r.fullName.toLowerCase().includes(needle) ||
      r.organization.toLowerCase().includes(needle) ||
      r.email.toLowerCase().includes(needle)
    );
  });
}

export function daysSince(iso: string, now: Date = new Date()): number {
  const then = new Date(iso).getTime();
  return Math.floor((now.getTime() - then) / (1000 * 60 * 60 * 24));
}

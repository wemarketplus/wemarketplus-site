import { ReferralSourceStatus as Status } from '@/shared/types';
import type { ReferralSource, ReferralSourceStatus } from '@/shared/types';
import type { ReferralSourceRecord } from '../types/referralsTypes';

// The backend ReferralSourceResponseDto (name/type/aiScore/...) is leaner than
// the UI's ReferralSource view-model; derive display-only fields from the AI
// score so the existing table/cards render without changes.
function scoreToStatus(score: number): ReferralSourceStatus {
  if (score >= 7) return Status.Green;
  if (score >= 4) return Status.Building;
  return Status.Red;
}

function scoreToTrust(score: number): ReferralSource['trustLevel'] {
  return Math.min(5, Math.max(1, Math.round(score / 2))) as ReferralSource['trustLevel'];
}

function scoreToPriority(score: number): ReferralSource['priorityLevel'] {
  if (score >= 7) return 'A';
  if (score >= 4) return 'B';
  return 'C';
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
    status: scoreToStatus(r.aiScore),
    trustLevel: scoreToTrust(r.aiScore),
    priorityLevel: scoreToPriority(r.aiScore),
    lastContactDate: r.updatedAt,
    assignedMarketer: '',
    territoryArea: [r.city, r.state].filter(Boolean).join(', ') || undefined,
    referralCount: 0,
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

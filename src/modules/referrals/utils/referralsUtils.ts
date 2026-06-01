import type { ReferralSource, ReferralSourceStatus } from '@/shared/types';

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

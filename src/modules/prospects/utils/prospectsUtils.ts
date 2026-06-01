import type { Prospect, ProspectStatus, Urgency } from '@/shared/types';

interface FilterArgs {
  search: string;
  status: ProspectStatus | 'all';
  urgency: Urgency | 'all';
}

export function filterProspects(
  prospects: readonly Prospect[],
  { search, status, urgency }: FilterArgs,
): readonly Prospect[] {
  const needle = search.trim().toLowerCase();
  return prospects.filter((p) => {
    if (status !== 'all' && p.status !== status) return false;
    if (urgency !== 'all' && p.urgency !== urgency) return false;
    if (!needle) return true;
    return (
      p.name.toLowerCase().includes(needle) ||
      p.email.toLowerCase().includes(needle) ||
      p.referralSource.toLowerCase().includes(needle)
    );
  });
}

import type { Prospect, ProspectStatus } from '@/shared/types';

export function groupProspectsByStatus(
  prospects: readonly Prospect[],
): Record<ProspectStatus, Prospect[]> {
  const acc: Record<string, Prospect[]> = {};
  for (const p of prospects) {
    (acc[p.status] ??= []).push(p);
  }
  return acc as Record<ProspectStatus, Prospect[]>;
}

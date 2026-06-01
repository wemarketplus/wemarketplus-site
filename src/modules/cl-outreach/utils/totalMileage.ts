import type { MileageEntry } from '@/shared/types';

export function totalMiles(entries: readonly MileageEntry[]): number {
  return entries.reduce((n, e) => n + e.distanceMiles, 0);
}

import type { Tour } from '@/shared/types';

export function sortByDate(tours: readonly Tour[]): Tour[] {
  return [...tours].sort(
    (a, b) => new Date(a.tourDate).getTime() - new Date(b.tourDate).getTime(),
  );
}

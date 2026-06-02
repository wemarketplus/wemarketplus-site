import { PROSPECTS_FIXTURE } from '@/shared/fixtures';
import type { Prospect } from '@/shared/types';

export function useCalendarEvents(): readonly Prospect[] {
  return [...PROSPECTS_FIXTURE].sort(
    (a, b) =>
      new Date(a.followUpDate).getTime() - new Date(b.followUpDate).getTime(),
  );
}

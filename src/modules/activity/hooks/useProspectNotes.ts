import { PROSPECT_NOTES_FIXTURE } from '@/shared/fixtures';
import type { ProspectNote } from '@/shared/types';

export function useProspectNotes(): {
  notes: readonly ProspectNote[];
  isUsingFixture: boolean;
} {
  return { notes: PROSPECT_NOTES_FIXTURE, isUsingFixture: true };
}

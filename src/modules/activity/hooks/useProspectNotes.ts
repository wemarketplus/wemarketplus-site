import { useMemo } from 'react';
import { PROSPECT_NOTES_FIXTURE } from '@/shared/fixtures';
import type { ProspectNote } from '@/shared/types';
import { useListNotesQuery } from '../api/activityApi';
import { toProspectNote } from '../utils/activityMappers';

export function useProspectNotes(): {
  notes: readonly ProspectNote[];
  isUsingFixture: boolean;
} {
  const { data } = useListNotesQuery();
  const notes = useMemo(
    () => (data ? data.data.map(toProspectNote) : PROSPECT_NOTES_FIXTURE),
    [data],
  );
  return { notes, isUsingFixture: !data };
}

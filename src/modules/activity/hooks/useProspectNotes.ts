import { useMemo } from 'react';
import type { ProspectNote } from '@/shared/types';
import { useListNotesQuery } from '../api/activityApi';
import { toProspectNote } from '../utils/activityMappers';

export function useProspectNotes(): {
  notes: readonly ProspectNote[];
  isUsingFixture: boolean;
} {
  const { data } = useListNotesQuery();
  const notes = useMemo(
    () => (data ? data.data.map(toProspectNote) : []),
    [data],
  );
  return { notes, isUsingFixture: false };
}

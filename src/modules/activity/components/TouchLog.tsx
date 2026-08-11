import { Flame } from 'lucide-react';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { activityTypeLabel } from '../utils/activityUtils';
import { TeamOnlyPill } from './TeamOnlyPill';
import type { NoteRecord } from '../types/activityTypes';

interface TouchLogProps {
  notes: readonly NoteRecord[];
  isLoading: boolean;
  /** Copy for the empty state — the caller knows what it is a log OF. */
  emptyLabel: string;
}

/**
 * The interaction history for a record: who was contacted, when, what kind of
 * interaction it was, and what was said.
 *
 * Renders `notes`, because notes ARE the touch log — the backend gave them a
 * canonical `activityType` and three possible targets (prospect, referral source,
 * contact) precisely so one activity record could serve all three. A separate
 * "interactions" concept would have been a second history for the same events.
 *
 * Shared rather than per-module for the same reason: the facility's touch log and
 * a prospect's team notes are the same list filtered differently, and two copies
 * would drift the moment either grew a field.
 */
export function TouchLog({ notes, isLoading, emptyLabel }: TouchLogProps) {
  if (isLoading) {
    return <p className="px-1 py-4 text-xs text-muted-soft">Loading history…</p>;
  }

  if (notes.length === 0) {
    return <p className="px-1 py-4 text-xs text-muted-soft">{emptyLabel}</p>;
  }

  return (
    <ul className="divide-y divide-border">
      {notes.map((note) => {
        // Empty for a note written before `activityType` existed. Derived by the
        // same helper the Notes screen uses, so one note describes itself
        // identically on both surfaces.
        const type = activityTypeLabel(note);
        return (
          <li key={note.id} className="flex flex-col gap-1.5 py-3">
            <div className="flex flex-wrap items-center gap-2">
              {type && <Pill tone="b">{type}</Pill>}
              {note.isHotLead && (
                <Pill tone="r">
                  <Flame className="mr-1 inline h-3 w-3" />
                  Hot
                </Pill>
              )}
              {/* Shared with the Notes screen so the same flag reads the same
                  way wherever a note surfaces. */}
              {note.isFamilySensitive && <TeamOnlyPill />}
              <span className="ml-auto text-[11px] text-muted-soft">
                {formatDate(note.createdAt)}
              </span>
            </div>

            <p className="text-sm text-foreground">{note.summary}</p>

            {note.nextStep && (
              <p className="text-xs text-muted">
                <span className="text-muted-soft">Next step:</span>{' '}
                {note.nextStep}
              </p>
            )}
            {note.followUpDate && (
              <p className="text-[11px] text-muted-soft">
                Follow-up {formatDate(note.followUpDate)}
                {/* The reminder is created by the backend from followUpDate, so
                    saying so here is a statement of fact, not a promise. */}
                {note.followUpReminderId && ' · reminder created'}
              </p>
            )}
          </li>
        );
      })}
    </ul>
  );
}

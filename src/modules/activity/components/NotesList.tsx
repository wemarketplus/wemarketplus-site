import { Card, CardContent } from '@/shared/ui/core';
import {
  URGENCY_LABELS,
  URGENCY_TONE,
} from '@/shared/constants/urgencyConstants';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import { useProspectNotes } from '../hooks/useProspectNotes';

export function NotesList() {
  const { notes } = useProspectNotes();

  if (notes.length === 0) {
    return (
      <Card>
        <CardContent className="p-10 text-center text-sm text-muted">
          No structured notes recorded yet.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {notes.map((n) => (
        <Card key={n.id}>
          <CardContent className="space-y-3 px-6 py-5">
            <header className="flex items-center justify-between gap-3">
              <div>
                <p className="text-sm font-semibold text-foreground">
                  {n.author}
                  <span className="ml-1 text-muted-soft">· {n.position}</span>
                </p>
                <p className="text-xs text-muted-soft">
                  {n.interactionType} · {n.contactType}
                </p>
              </div>
              <span
                className={`shrink-0 rounded-pill border px-2.5 py-0.5 text-[10px] uppercase tracking-[0.08em] ${URGENCY_TONE[n.urgency]}`}
              >
                {URGENCY_LABELS[n.urgency]}
              </span>
            </header>
            <p className="text-sm text-foreground">{n.summary}</p>
            {n.patientStatus && (
              <p className="text-xs text-muted">
                <span className="font-semibold text-muted-soft">Status: </span>
                {n.patientStatus}
              </p>
            )}
            {n.barriers && (
              <p className="text-xs text-muted">
                <span className="font-semibold text-muted-soft">Barriers: </span>
                {n.barriers}
              </p>
            )}
            <p className="text-xs text-primary">
              <span className="font-semibold">Next step: </span>
              {n.nextStep}
            </p>
            <p className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
              {formatDateTime(n.date)} · {n.assignedTo}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

import { Button, Card, CardContent } from '@/shared/ui/core';
import { EntityRowActions } from '@/shared/ui/entity';
import { useRole, STAFF_ROLES } from '@/shared/rbac';
import {
  URGENCY_LABELS,
  URGENCY_TONE,
} from '@/shared/constants/urgencyConstants';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import { Plus } from 'lucide-react';
import { useProspectNotes } from '../hooks/useProspectNotes';
import { NoteFormModal } from './NoteFormModal';

export function NotesList() {
  const { notes, records, crud, submit } = useProspectNotes();

  // Add/edit is a staff action; read-only roles see the list without controls.
  const { isAny } = useRole();
  const canEdit = isAny(STAFF_ROLES);

  const modal = canEdit ? (
    <NoteFormModal
      open={crud.createOpen || crud.editing !== null}
      isSaving={crud.isSaving}
      editing={crud.editing}
      onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
      onSubmit={submit}
    />
  ) : null;

  return (
    <div className="space-y-3">
      {canEdit && (
        <div className="flex justify-end">
          <Button size="sm" onClick={crud.openCreate}>
            <Plus className="h-4 w-4" />
            Add note
          </Button>
        </div>
      )}

      {notes.length === 0 ? (
        <Card>
          <CardContent className="p-10 text-center text-sm text-muted">
            No structured notes recorded yet.
          </CardContent>
        </Card>
      ) : (
        notes.map((n) => (
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
                <div className="flex shrink-0 items-center gap-2">
                  <span
                    className={`rounded-pill border px-2.5 py-0.5 text-[10px] uppercase tracking-[0.08em] ${URGENCY_TONE[n.urgency]}`}
                  >
                    {URGENCY_LABELS[n.urgency]}
                  </span>
                  {canEdit && (
                    <EntityRowActions
                      onEdit={() => {
                        const record = records.find((r) => r.id === n.id);
                        if (record) crud.openEdit(record);
                      }}
                    />
                  )}
                </div>
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
        ))
      )}

      {modal}
    </div>
  );
}

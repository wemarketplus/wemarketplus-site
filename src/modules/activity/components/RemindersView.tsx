import { Plus } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { EntityRowActions } from '@/shared/ui/entity';
import { useRole, STAFF_ROLES } from '@/shared/rbac';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  REMINDER_BUCKETS,
  REMINDER_BUCKET_LABELS,
  REMINDER_BUCKET_TONE,
} from '../constants/activityConstants';
import { useReminders } from '../hooks/useReminders';
import { ReminderFormModal } from './ReminderFormModal';

export function RemindersView() {
  const { buckets, crud, submit, recordById } = useReminders();

  // Add/edit/delete is a staff action; read-only roles see the list only.
  const { isAny } = useRole();
  const canEdit = isAny(STAFF_ROLES);

  const edit = (id: string) => {
    const record = recordById(id);
    if (record) crud.openEdit(record);
  };
  const remove = (id: string) => {
    const record = recordById(id);
    if (record) crud.confirmDelete(record);
  };

  const empty = REMINDER_BUCKETS.every((b) => buckets[b].length === 0);

  return (
    <div className="space-y-3">
      {canEdit && (
        <div className="flex justify-end">
          <Button size="sm" onClick={crud.openCreate}>
            <Plus className="h-4 w-4" />
            Add reminder
          </Button>
        </div>
      )}

      {empty ? (
        <Card>
          <CardContent className="p-10 text-center text-sm text-muted">
            No upcoming reminders.
          </CardContent>
        </Card>
      ) : (
        REMINDER_BUCKETS.map((bucket) => {
          const items = buckets[bucket];
          if (items.length === 0) return null;
          return (
            <Card key={bucket}>
              <CardContent className="px-0 pt-0 pb-0">
                <header className="flex items-center justify-between px-6 py-3">
                  <span
                    className={`rounded-pill border px-2.5 py-0.5 text-[10px] uppercase tracking-[0.08em] ${REMINDER_BUCKET_TONE[bucket]}`}
                  >
                    {REMINDER_BUCKET_LABELS[bucket]}
                  </span>
                  <span className="text-[10px] text-muted-soft">{items.length}</span>
                </header>
                <ul className="divide-y divide-white/[0.06] border-t border-border/[0.06]">
                  {items.map((r) => (
                    <li key={r.id} className="flex items-start justify-between gap-3 px-6 py-3">
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-foreground">
                          {r.sourceName}
                        </p>
                        <p className="mt-0.5 text-xs text-muted">{r.actionDescription}</p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <span className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                          {formatDate(r.dueDate)}
                        </span>
                        {canEdit && (
                          <EntityRowActions
                            onEdit={() => edit(r.id)}
                            onDelete={() => remove(r.id)}
                          />
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          );
        })
      )}

      {canEdit && (
        <ReminderFormModal
          open={crud.createOpen || crud.editing !== null}
          isSaving={crud.isSaving}
          editing={crud.editing}
          onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
          onSubmit={submit}
        />
      )}
    </div>
  );
}

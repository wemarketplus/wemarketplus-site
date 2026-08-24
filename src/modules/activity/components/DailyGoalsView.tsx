import { Plus } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { EntityRowActions } from '@/shared/ui/entity';
import { useRole, HL_FIELD_ROLES, STAFF_ROLES } from '@/shared/rbac';
import { cn } from '@/shared/utils/cn';
import { useDailyGoals } from '../hooks/useDailyGoals';
import { computeGoalProgress } from '../utils/activityUtils';
import { GoalFormModal } from './GoalFormModal';

export function DailyGoalsView() {
  const { goals, crud, submit, recordById } = useDailyGoals();

  const { isAny } = useRole();
  // A field user sets their OWN goals — that is the point of a daily goal. The
  // backend scopes anything they create to themselves and refuses edits to
  // anyone else's, so this affordance cannot be widened by the client.
  const canEdit = isAny(HL_FIELD_ROLES);
  // Deleting stays management-only, matching the backend's @Roles on
  // DELETE /goals/:id. Showing the action to a marketer would only produce a
  // 403 they cannot act on.
  const canDelete = isAny(STAFF_ROLES);

  const edit = (id: string) => {
    const record = recordById(id);
    if (record) crud.openEdit(record);
  };
  const remove = (id: string) => {
    const record = recordById(id);
    if (record) crud.confirmDelete(record);
  };

  return (
    <div className="space-y-4">
      {canEdit && (
        <div className="flex justify-end">
          <Button size="sm" onClick={crud.openCreate}>
            <Plus className="h-4 w-4" />
            Add goal
          </Button>
        </div>
      )}

      {goals.length === 0 ? (
        <Card>
          <CardContent className="p-10 text-center text-sm text-muted">
            No goals set yet.
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {goals.map((g) => {
            const { pct, hit } = computeGoalProgress(g.current, g.target);
            return (
              <Card key={g.id}>
                <CardContent className="space-y-3 px-5 py-5">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-[10px] uppercase tracking-label text-muted-soft">
                      {g.label}
                    </p>
                    {canEdit && (
                      <EntityRowActions
                        onEdit={() => edit(g.id)}
                        onDelete={canDelete ? () => remove(g.id) : undefined}
                      />
                    )}
                  </div>
                  <p className="font-display text-3xl leading-none text-foreground">
                    {g.current}
                    <span className="text-base text-muted-soft"> / {g.target}</span>
                  </p>
                  <div className="h-1.5 w-full overflow-hidden rounded-pill bg-foreground/[0.06]">
                    <div
                      className={cn(
                        'h-full rounded-pill transition-all',
                        hit ? 'bg-success' : 'bg-primary',
                      )}
                      style={{ width: `${pct}%` }}
                    />
                  </div>

                  {/* Daily and weekly pacing, shown only for a TRACKED goal —
                      a manual goal has no activity behind it to break down, and
                      rendering zeroes would imply nothing had happened. */}
                  {g.isTracked && (
                    <p className="text-[11px] text-muted-soft">
                      <span className="text-muted">Today</span> {g.today ?? 0}
                      <span className="mx-1.5">·</span>
                      <span className="text-muted">This week</span>{' '}
                      {g.weekToDate ?? 0}
                      <span className="ml-1.5 text-muted-soft">
                        · tracked automatically
                      </span>
                    </p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {canEdit && (
        <GoalFormModal
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

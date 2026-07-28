import { Plus } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { EntityRowActions } from '@/shared/ui/entity';
import { useRole, STAFF_ROLES } from '@/shared/rbac';
import { cn } from '@/shared/utils/cn';
import { useDailyGoals } from '../hooks/useDailyGoals';
import { computeGoalProgress } from '../utils/activityUtils';
import { GoalFormModal } from './GoalFormModal';

export function DailyGoalsView() {
  const { goals, crud, submit, recordById } = useDailyGoals();

  // Add/edit/delete is a staff action; read-only roles see the tiles only.
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
                    <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
                      {g.label}
                    </p>
                    {canEdit && (
                      <EntityRowActions
                        onEdit={() => edit(g.id)}
                        onDelete={() => remove(g.id)}
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

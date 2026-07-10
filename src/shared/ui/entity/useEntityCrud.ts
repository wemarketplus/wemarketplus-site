import { useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';

// Minimal shape of an RTK Query mutation trigger — call it, then `.unwrap()`.
type MutationTrigger<TArg, TResult> = (arg: TArg) => { unwrap: () => Promise<TResult> };

interface UseEntityCrudArgs<TEntity, TCreate, TUpdate> {
  // Human label for toasts, e.g. "contact".
  noun: string;
  create: MutationTrigger<TCreate, TEntity>;
  update: MutationTrigger<{ id: string; patch: TUpdate }, TEntity>;
  remove: MutationTrigger<string, unknown>;
  isSaving: boolean;
  // Given a row, produce its display label for the delete confirm + toast.
  labelOf: (entity: TEntity) => string;
}

// Orchestrates the create/edit/delete lifecycle for one entity: modal open
// state, the row being edited, and the three mutations wrapped with
// success/error toasts. Components stay free of API + side-effect logic — they
// call openCreate/openEdit/submitCreate/submitUpdate/confirmDelete. Mirrors the
// prospects/users hook conventions, generalized so every module reuses it.
export function useEntityCrud<
  TEntity extends { id: string },
  TCreate,
  TUpdate,
>({ noun, create, update, remove, isSaving, labelOf }: UseEntityCrudArgs<TEntity, TCreate, TUpdate>) {
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<TEntity | null>(null);

  const submitCreate = async (body: TCreate): Promise<boolean> => {
    try {
      await create(body).unwrap();
      toast.success(`${cap(noun)} added`);
      setCreateOpen(false);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, `Could not add ${noun}. Please try again.`));
      return false;
    }
  };

  const submitUpdate = async (id: string, patch: TUpdate): Promise<boolean> => {
    try {
      await update({ id, patch }).unwrap();
      toast.success(`${cap(noun)} updated`);
      setEditing(null);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, `Could not update ${noun}. Please try again.`));
      return false;
    }
  };

  const confirmDelete = async (entity: TEntity): Promise<void> => {
    const label = labelOf(entity);
    if (!window.confirm(`Delete ${label}? This cannot be undone.`)) return;
    try {
      await remove(entity.id).unwrap();
      toast.success(`Deleted ${label}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, `Could not delete ${noun}.`));
    }
  };

  return {
    createOpen,
    openCreate: () => setCreateOpen(true),
    closeCreate: () => setCreateOpen(false),
    editing,
    openEdit: (entity: TEntity) => setEditing(entity),
    closeEdit: () => setEditing(null),
    isSaving,
    submitCreate,
    submitUpdate,
    confirmDelete,
  };
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

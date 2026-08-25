import { useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { confirm } from '@/shared/ui/feedback';

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
      /**
       * ONE toast for a burst, via a stable id.
       *
       * Unlike create (one modal, one submit) and delete (behind a confirm),
       * this path is reachable once PER ROW: every list table's status badge
       * PATCHes on change, so anything that touches several rows at once — a
       * browser autofill sweeping the table, a bulk action — used to stack N
       * separate "…updated" popups, capped only by sonner's 3-visible default.
       * That is the "multiple Update popups" report. Sonner treats a repeated
       * id as the SAME toast, so N concurrent updates now render as one
       * message. The per-row PATCHes are unaffected; only the announcement
       * collapses.
       */
      toast.success(`${cap(noun)} updated`, { id: `${noun}-updated` });
      setEditing(null);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, `Could not update ${noun}. Please try again.`));
      return false;
    }
  };

  const confirmDelete = async (entity: TEntity): Promise<void> => {
    const label = labelOf(entity);
    const ok = await confirm({
      title: `Delete ${label}?`,
      body: `${label} will be permanently removed.`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    try {
      await remove(entity.id).unwrap();
      toast.success(`Deleted ${label}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, `Could not delete ${noun}.`));
    }
  };

  /**
   * `createOpen` and `editing` are separate state but they drive ONE modal —
   * every consumer renders it as `open={createOpen || editing !== null}` with
   * `onClose={editing ? closeEdit : closeCreate}`. So they have to be mutually
   * exclusive, and they were not: nothing behind an open modal is inert (Modal
   * has no focus trap), so a row's Edit button was still reachable by keyboard
   * while "Add" was up. Both flags then set meant the Add form silently
   * retitled to Edit and re-`reset` to that row, `submit` routed to
   * submitUpdate — the only way an ADD flow can emit "…updated" at all — and
   * one click on Cancel cleared just the one flag, leaving the modal open.
   *
   * Fixed here rather than at ~15 call sites: each opener clears the other
   * flag, and each closer clears both, so `open` cannot be true with the
   * component in a state no one asked for.
   */
  return {
    createOpen,
    openCreate: () => {
      setEditing(null);
      setCreateOpen(true);
    },
    closeCreate: () => {
      setEditing(null);
      setCreateOpen(false);
    },
    editing,
    openEdit: (entity: TEntity) => {
      setCreateOpen(false);
      setEditing(entity);
    },
    closeEdit: () => {
      setCreateOpen(false);
      setEditing(null);
    },
    isSaving,
    submitCreate,
    submitUpdate,
    confirmDelete,
  };
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

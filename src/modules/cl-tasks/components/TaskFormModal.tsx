import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal, type EntitySelectOption } from '@/shared/ui/entity';
import { CL_TASK_STATUS, TICKET_PRIORITY, type ClTaskRecord } from '@/modules/cl-outreach';
import { TASK_FIELDS } from '../constants/tasksConstants';
import { taskSchema, type TaskFormValues } from '../schema/taskSchema';
import { toTaskFormValues } from '../utils/tasksUtils';

const EMPTY: TaskFormValues = {
  title: '',
  priority: TICKET_PRIORITY.Medium,
  status: CL_TASK_STATUS.Open,
  assignedTo: '',
  dueDate: '',
  description: '',
};

interface TaskFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: ClTaskRecord | null;
  /** Tenant staff for the "Assigned to" picker. Undefined while still loading. */
  staffOptions: readonly EntitySelectOption[] | undefined;
  onClose: () => void;
  onSubmit: (values: TaskFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function TaskFormModal({
  open,
  isSaving,
  editing,
  staffOptions,
  onClose,
  onSubmit,
}: TaskFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TaskFormValues>({
    resolver: zodResolver(taskSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toTaskFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <EntityFormModal<TaskFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit task' : 'Add new task'}
      submitLabel={editing ? 'Save changes' : 'Save task'}
      fields={TASK_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
      // Keyed by field name — how EntityFormModal feeds a `lookup` its options.
      lookups={{ assignedTo: staffOptions }}
    />
  );
}

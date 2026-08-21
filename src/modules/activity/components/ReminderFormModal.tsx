import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import { TASK_FIELDS } from '../constants/activityConstants';
import { taskSchema, type TaskFormValues } from '../schema/taskSchema';
import { toTaskFormValues } from '../utils/activityMappers';
import { TaskPriority, TaskStatus } from '../types/activityTypes';
import type { TaskRecord } from '../types/activityTypes';

const EMPTY: TaskFormValues = {
  title: '',
  description: '',
  dueDate: '',
  priority: TaskPriority.Medium,
  status: TaskStatus.Pending,
};

interface ReminderFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: TaskRecord | null;
  onClose: () => void;
  onSubmit: (values: TaskFormValues) => Promise<boolean>;
}

// Reminders are tasks with a due date. Owns the react-hook-form instance for
// create + edit and delegates rendering to the shared EntityFormModal.
export function ReminderFormModal({ open, isSaving, editing, onClose, onSubmit }: ReminderFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    setError,
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
    // Only on CREATE, and only the picker's own past-date rule (mirrors the
    // `min` on the date field and CreateTaskDto's IsNotPastDateConstraint) —
    // never on edit, so saving an unrelated change to an already-overdue
    // reminder (title, priority, marking it done) is never blocked by a due
    // date the user did not touch.
    if (!editing && values.dueDate && values.dueDate < todayLocalDate()) {
      setError('dueDate', { message: 'Due date cannot be in the past.' });
      return;
    }
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <EntityFormModal<TaskFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit reminder' : 'Add reminder'}
      submitLabel={editing ? 'Save changes' : 'Save reminder'}
      fields={TASK_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}

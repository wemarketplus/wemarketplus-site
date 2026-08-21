import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal, type EntitySelectOption } from '@/shared/ui/entity';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
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
    /**
     * A task cannot be due on a day that has already gone.
     *
     * Sits between the two other layers of the same rule rather than replacing
     * either: `min: todayLocalDate` on the field greys out past days in the
     * picker, and `@IsNotPastDate()` on CreateClTaskDto rejects them on the
     * wire. This layer exists because the date input still accepts a TYPED
     * value the calendar would never have offered, and it turns what would be a
     * raw 400 toast into an error message under the field.
     *
     * Two conditions, both deliberate, and identical to the lead follow-up
     * date's rule (LeadFormModal): only on create, and on edit only when the
     * user actually CHANGED the date. A task that quietly went overdue has to
     * stay editable — marking it done, or fixing its title, must not be blocked
     * by a due date nobody touched. That is also why the server-side rule is on
     * the create DTO alone and not on UpdateClTaskDto.
     */
    const changedDate = !editing || values.dueDate !== (editing.dueDate ?? '');
    if (changedDate && values.dueDate && values.dueDate < todayLocalDate()) {
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

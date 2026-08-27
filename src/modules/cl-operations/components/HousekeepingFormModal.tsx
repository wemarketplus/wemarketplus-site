import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal, type EntitySelectOption } from '@/shared/ui/entity';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import { HOUSEKEEPING_STATUS } from '../constants/clOperationsApiConstants';
import { HOUSEKEEPING_FIELDS } from '../constants/clOperationsConstants';
import { housekeepingSchema, type HousekeepingFormValues } from '../schema/clOperationsSchema';
import { toHousekeepingFormValues } from '../utils/clOperationsMappers';
import type { ClHousekeepingTaskRecord } from '../types/clOperationsApiTypes';

const EMPTY: HousekeepingFormValues = {
  taskType: '',
  area: '',
  status: HOUSEKEEPING_STATUS.Pending,
  assignedTo: '',
  dueDate: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClHousekeepingTaskRecord | null;
  /** Tenant staff for the "Assigned to" picker. Undefined while still loading. */
  staffOptions: readonly EntitySelectOption[] | undefined;
  onClose: () => void;
  onSubmit: (values: HousekeepingFormValues) => Promise<boolean>;
}

export function HousekeepingFormModal({
  open,
  isSaving,
  editing,
  staffOptions,
  onClose,
  onSubmit,
}: Props) {
  const {
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors },
  } = useForm<HousekeepingFormValues>({
    resolver: zodResolver(housekeepingSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toHousekeepingFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    /**
     * A clean cannot be due on a day that has already gone.
     *
     * The middle of the same three layers the task and lead follow-up dates use
     * (see TaskFormModal, which this mirrors deliberately): `min: todayLocalDate`
     * greys out past days in the picker, and @IsNotPastDate on
     * CreateClHousekeepingTaskDto rejects them on the wire. This layer exists
     * because the date field still accepts a TYPED value the calendar would never
     * have offered, and it turns what would otherwise be a raw 400 toast into a
     * message under the field.
     *
     * Two conditions, both deliberate: only on create, and on edit only when the
     * user actually CHANGED the date. A task that quietly went overdue has to
     * stay editable — marking it complete, or fixing its area, must not be
     * blocked by a due date nobody touched. Same reason the server-side rule sits
     * on the create DTO alone.
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
    <EntityFormModal<HousekeepingFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit task' : 'Assign housekeeping task'}
      submitLabel={editing ? 'Save changes' : 'Assign task'}
      fields={HOUSEKEEPING_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
      // Keyed by field name, which is how EntityFormModal feeds a `lookup` field
      // its options. Undefined while loading renders the picker disabled rather
      // than empty — an empty staff list reads as "nobody works here".
      lookups={{ assignedTo: staffOptions }}
    />
  );
}

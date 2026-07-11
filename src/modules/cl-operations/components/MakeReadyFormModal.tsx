import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { MAKE_READY_STATUS } from '../constants/clOperationsApiConstants';
import { MAKE_READY_STATUS_OPTIONS } from '../constants/clOperationsConstants';
import { makeReadySchema, type MakeReadyFormValues } from '../schema/clOperationsSchema';
import { toMakeReadyFormValues } from '../utils/clOperationsMappers';
import type { ClMakeReadyTaskRecord } from '../types/clOperationsApiTypes';

const EMPTY: MakeReadyFormValues = {
  apartmentId: '',
  taskName: '',
  status: MAKE_READY_STATUS.Pending,
  dueDate: '',
  notes: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClMakeReadyTaskRecord | null;
  apartmentOptions: readonly EntitySelectOption[];
  onClose: () => void;
  onSubmit: (values: MakeReadyFormValues) => Promise<boolean>;
}

export function MakeReadyFormModal({
  open,
  isSaving,
  editing,
  apartmentOptions,
  onClose,
  onSubmit,
}: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<MakeReadyFormValues>({
    resolver: zodResolver(makeReadySchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    const seed = editing
      ? toMakeReadyFormValues(editing)
      : { ...EMPTY, apartmentId: apartmentOptions[0]?.value ?? '' };
    reset(seed);
  }, [open, editing, apartmentOptions, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <Modal
      open={open}
      onClose={close}
      title={editing ? 'Edit make-ready task' : 'Add make-ready task'}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Saving…' : editing ? 'Save changes' : 'Add task'}
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="mr-unit">Unit</Label>
          <Select id="mr-unit" {...register('apartmentId')}>
            <option value="">— Select unit —</option>
            {apartmentOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
          {errors.apartmentId && (
            <p className="mt-1 text-[12px] text-destructive">{errors.apartmentId.message}</p>
          )}
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="mr-task">Task name</Label>
          <Input id="mr-task" placeholder="Paint touch-up" {...register('taskName')} />
          {errors.taskName && (
            <p className="mt-1 text-[12px] text-destructive">{errors.taskName.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="mr-status">Status</Label>
          <Select id="mr-status" {...register('status')}>
            {MAKE_READY_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="mr-due">Due date</Label>
          <Input id="mr-due" type="date" {...register('dueDate')} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="mr-notes">Notes</Label>
          <Textarea id="mr-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}

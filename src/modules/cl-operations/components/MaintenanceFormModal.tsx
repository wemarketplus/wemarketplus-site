import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { MAINTENANCE_STATUS, TICKET_PRIORITY } from '../constants/clOperationsApiConstants';
import { MAINTENANCE_FIELDS } from '../constants/clOperationsConstants';
import { maintenanceSchema, type MaintenanceFormValues } from '../schema/clOperationsSchema';
import { toMaintenanceFormValues } from '../utils/clOperationsMappers';
import type { ClMaintenanceTicketRecord } from '../types/clOperationsApiTypes';

const EMPTY: MaintenanceFormValues = {
  issue: '',
  ticketNumber: '',
  priority: TICKET_PRIORITY.Medium,
  status: MAINTENANCE_STATUS.Open,
  reporterName: '',
  resolution: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClMaintenanceTicketRecord | null;
  onClose: () => void;
  onSubmit: (values: MaintenanceFormValues) => Promise<boolean>;
}

export function MaintenanceFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<MaintenanceFormValues>({
    resolver: zodResolver(maintenanceSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toMaintenanceFormValues(editing) : EMPTY);
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
    <EntityFormModal<MaintenanceFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit ticket' : 'New maintenance ticket'}
      submitLabel={editing ? 'Save changes' : 'Create ticket'}
      fields={MAINTENANCE_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}

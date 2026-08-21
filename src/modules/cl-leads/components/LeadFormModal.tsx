import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import { CL_CARE_LEVEL, CL_LEAD_STAGE, CL_URGENCY } from '../constants/clLeadApiConstants';
import { LEAD_FIELDS } from '../constants/leadsConstants';
import { leadSchema, type LeadFormValues } from '../schema/leadSchema';
import { toLeadFormValues } from '../utils/leadsUtils';
import type { ClLeadRecord } from '../types/clLeadApiTypes';

const EMPTY: LeadFormValues = {
  fullName: '',
  phone: '',
  email: '',
  careLevel: CL_CARE_LEVEL.IndependentLiving,
  stage: CL_LEAD_STAGE.Inquiry,
  urgency: CL_URGENCY.Warm,
  source: '',
  followUpDate: '',
  notes: '',
};

interface LeadFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: ClLeadRecord | null;
  onClose: () => void;
  onSubmit: (values: LeadFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function LeadFormModal({ open, isSaving, editing, onClose, onSubmit }: LeadFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors },
  } = useForm<LeadFormValues>({
    resolver: zodResolver(leadSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toLeadFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    /**
     * A follow-up cannot be scheduled for a day that has gone. Mirrors the
     * `min` on the field and IsNotPastDate on CreateClLeadDto, and exists in
     * between them because the picker lets a keyboard user type a date the
     * calendar would not have offered.
     *
     * Two conditions, both deliberate. Only on CREATE, and on edit only when the
     * user actually CHANGED the date: a lead whose follow-up quietly went
     * overdue must stay editable — correcting its phone number cannot be blocked
     * by a field nobody touched. That is the same rule the server applies by
     * putting IsNotPastDate on the create DTO alone, enforced here for the one
     * case the server cannot see (an edit that moves the date backwards).
     */
    const changedDate = !editing || values.followUpDate !== (editing.followUpDate ?? '');
    if (changedDate && values.followUpDate && values.followUpDate < todayLocalDate()) {
      setError('followUpDate', {
        message: 'Follow-up date cannot be in the past.',
      });
      return;
    }
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <EntityFormModal<LeadFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit lead' : 'Add new lead'}
      submitLabel={editing ? 'Save changes' : 'Save lead'}
      fields={LEAD_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}

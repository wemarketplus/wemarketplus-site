import { zodResolver } from '@hookform/resolvers/zod';
import { useMemo } from 'react';
import { Controller, useForm } from 'react-hook-form';
import {
  Button,
  DatePicker,
  Input,
  Label,
  ListboxSelect,
  Select,
  Textarea,
} from '@/shared/ui/core';
import { useCompanyNameOptions } from '@/shared/hooks/useSharedLookups';
import { Modal } from '@/shared/ui/feedback';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import { LEAD_SOURCE_OPTIONS } from '../constants/leadsConstants';
import { newLeadSchema, type NewLeadFormValues } from '../schema/leadSchema';
import { LeadSourceType } from '../types/leadsTypes';

interface AddLeadModalProps {
  open: boolean;
  isSaving: boolean;
  onClose: () => void;
  // Returns true when the create succeeded, so the form can reset.
  onSubmit: (values: NewLeadFormValues) => Promise<boolean>;
}

export function AddLeadModal({
  open,
  isSaving,
  onClose,
  onSubmit: submit,
}: AddLeadModalProps) {
  const {
    control,
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewLeadFormValues>({
    resolver: zodResolver(newLeadSchema),
    defaultValues: {
      sourceType: LeadSourceType.Fax,
      sourceDetail: '',
      patientName: '',
      patientDob: '',
      diagnosisReason: '',
      referringPerson: '',
      referringOrg: '',
    },
  });

  // Referring organisations come from the Companies tab rather than being typed:
  // free text spawned a new spelling of the same facility on every intake, which
  // is what made referral-source reporting unusable. Gated on `open` so closing
  // the modal is the whole cost of not needing the list.
  const companyOptions = useCompanyNameOptions(open);

  /**
   * The organisation choices, WITH the "none" row prepended.
   *
   * This list is the tenant's whole company book — useCompanyNameOptions asks
   * for LOOKUP_PAGE_SIZE (100) names — and a native <select> hands that count
   * straight to the browser, which draws a popup as tall as its option list
   * implies and places it over whatever is above the field. No CSS reaches that
   * popup (`size`, `max-height`, `overflow` all apply to the closed control
   * only), which is exactly the case <ListboxSelect> exists for: same
   * CONTROL_BASE/CONTROL_HEIGHT trigger as the <Select> it replaces, but a
   * panel capped at 264px with its own scrollbar.
   *
   * The blank row has to be a REAL option rather than the placeholder: a
   * placeholder only renders while the value matches nothing, so an
   * organisation picked by mistake could otherwise never be un-picked — and
   * `referringOrg` is optional (a lead may carry a patient name instead).
   * Loading and empty keep the exact copy the <option> carried before.
   */
  const orgChoices = useMemo(() => {
    if (!companyOptions) return [{ value: '', label: 'Loading…' }];
    if (companyOptions.length === 0) {
      return [{ value: '', label: 'No companies yet — add one in Companies' }];
    }
    return [{ value: '', label: '— No organisation —' }, ...companyOptions];
  }, [companyOptions]);

  const close = () => {
    reset();
    onClose();
  };

  const onSubmit = async (values: NewLeadFormValues) => {
    const ok = await submit(values);
    if (ok) reset();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Log inbound referral"
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Save lead'}
          </Button>
        </>
      }
    >
      <form
        autoComplete="off"
        onSubmit={handleSubmit(onSubmit)}
        className="grid grid-cols-1 gap-4 sm:grid-cols-2"
      >
        <div>
          <Label htmlFor="al-source">How did it arrive?</Label>
          <Select id="al-source" {...register('sourceType')}>
            {LEAD_SOURCE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="al-detail">Source detail</Label>
          <Input
            id="al-detail"
            placeholder="Fax line, form name, caller…"
            {...register('sourceDetail')}
          />
        </div>
        <div>
          <Label htmlFor="al-patient">Patient name</Label>
          <Input id="al-patient" {...register('patientName')} />
          {errors.patientName && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.patientName.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="al-dob">Patient DOB</Label>
          {/*
            `max` greys out every day after today in the calendar itself — the
            mirror of the `min: todayLocalDate` the follow-up/due-date fields
            carry. Called per render rather than captured at module load, so a
            modal left open across midnight moves its ceiling with the clock.
            Today stays pickable: the bound is inclusive (DatePicker's
            `isOutOfRange` only rejects `d > maxDate`).

            First of three layers, and the weakest — it does not stop a future
            date TYPED into the field, which DatePicker deliberately keeps so the
            form can report it. See the `patientDob` refine in leadSchema for the
            second, and IsNotFutureDate on Create/UpdateLeadDto for the one that
            protects the column.
          */}
          <DatePicker
            id="al-dob"
            max={todayLocalDate()}
            {...register('patientDob')}
          />
          {errors.patientDob && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.patientDob.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="al-person">Referring person</Label>
          <Input id="al-person" {...register('referringPerson')} />
        </div>
        <div>
          <Label htmlFor="al-org">Referring organisation</Label>
          <Controller
            control={control}
            name="referringOrg"
            render={({ field }) => (
              <ListboxSelect
                id="al-org"
                value={field.value ?? ''}
                onChange={field.onChange}
                onBlur={field.onBlur}
                options={orgChoices}
                placeholder="Select a company…"
                disabled={!companyOptions}
              />
            )}
          />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="al-reason">Diagnosis / reason</Label>
          <Textarea id="al-reason" {...register('diagnosisReason')} />
        </div>
      </form>
    </Modal>
  );
}

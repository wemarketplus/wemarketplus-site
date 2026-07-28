import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { JOB_TYPE_LABELS } from '@/modules/jobs/constants/jobsConstants';
import type { JobRecord } from '@/modules/jobs/types/jobsTypes';
import { Button, Input, Label, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { APPOINTMENT_TYPE_OPTIONS } from '../constants/appointmentsConstants';
import {
  newAppointmentSchema,
  type NewAppointmentFormValues,
} from '../schema/appointmentSchema';
import { AppointmentType } from '../types/appointmentsTypes';

interface ScheduleAppointmentModalProps {
  open: boolean;
  isSaving: boolean;
  /** Jobs an appointment can be attached to — an appointment always has a parent. */
  jobs: readonly JobRecord[];
  onClose: () => void;
  onSubmit: (values: NewAppointmentFormValues) => Promise<boolean>;
}

export function ScheduleAppointmentModal({
  open,
  isSaving,
  jobs,
  onClose,
  onSubmit: submit,
}: ScheduleAppointmentModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewAppointmentFormValues>({
    resolver: zodResolver(newAppointmentSchema),
    defaultValues: {
      jobId: '',
      title: '',
      startAt: '',
      endAt: '',
      appointmentType: AppointmentType.InPerson,
      location: '',
    },
  });

  const close = () => {
    reset();
    onClose();
  };

  const onSubmitForm = async (values: NewAppointmentFormValues) => {
    const ok = await submit(values);
    if (ok) reset();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Schedule appointment"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmitForm)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Schedule'}
          </Button>
        </>
      }
    >
      <form
        onSubmit={handleSubmit(onSubmitForm)}
        className="grid grid-cols-1 gap-4 sm:grid-cols-2"
      >
        <div className="sm:col-span-2">
          <Label htmlFor="sa-job">Job</Label>
          <Select id="sa-job" {...register('jobId')}>
            <option value="">Select a job…</option>
            {jobs.map((job) => (
              <option key={job.id} value={job.id}>
                {JOB_TYPE_LABELS[job.jobType]}
                {job.objective ? ` — ${job.objective}` : ''}
              </option>
            ))}
          </Select>
          {errors.jobId && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.jobId.message}
            </p>
          )}
          {jobs.length === 0 && (
            <p className="mt-1 text-[12px] text-muted-soft">
              No open jobs yet — move a pipeline card to spawn one, or create a job
              first.
            </p>
          )}
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="sa-title">Title</Label>
          <Input id="sa-title" {...register('title')} />
          {errors.title && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.title.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="sa-start">Starts</Label>
          <Input id="sa-start" type="datetime-local" {...register('startAt')} />
          {errors.startAt && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.startAt.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="sa-end">Ends</Label>
          <Input id="sa-end" type="datetime-local" {...register('endAt')} />
          {errors.endAt && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.endAt.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="sa-type">Type</Label>
          <Select id="sa-type" {...register('appointmentType')}>
            {APPOINTMENT_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="sa-location">Location</Label>
          <Input id="sa-location" {...register('location')} />
        </div>
      </form>
    </Modal>
  );
}

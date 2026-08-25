import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import {
  LocationField,
  toLocationValue,
  type LocationValue,
} from '@/modules/geocoding';
import { JOB_TYPE_LABELS } from '@/modules/jobs/constants/jobsConstants';
import type { JobRecord } from '@/modules/jobs/types/jobsTypes';
import { useTenantStaffOptions } from '@/modules/users';
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
  /** The job list is still in flight. An empty picker is not yet an empty list. */
  isLoadingJobs?: boolean;
  /** The job list request failed (or was refused), so the picker cannot fill. */
  isJobsError?: boolean;
  onClose: () => void;
  onSubmit: (values: NewAppointmentFormValues) => Promise<boolean>;
}

export function ScheduleAppointmentModal({
  open,
  isSaving,
  jobs,
  isLoadingJobs = false,
  isJobsError = false,
  onClose,
  onSubmit: submit,
}: ScheduleAppointmentModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
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
      assignedRep: '',
    },
  });

  // Open-gated so a closed modal holds no directory subscription.
  const staff = useTenantStaffOptions(open);

  const close = () => {
    reset();
    onClose();
  };

  /**
   * "Location" means two different things on this form, and only one of them is
   * a place: an in-person visit happens somewhere, while a video call or a phone
   * appointment carries a link or a number. So the map picker appears for
   * in-person only — offering a map for a Zoom URL would be asking the user to
   * pin a building that has nothing to do with the meeting.
   */
  const isInPerson = watch('appointmentType') === AppointmentType.InPerson;
  const location = toLocationValue(
    watch('location'),
    watch('locationLat'),
    watch('locationLng'),
  );

  const setLocation = (next: LocationValue) => {
    setValue('location', next.label, { shouldDirty: true });
    setValue('locationLat', next.coords?.lat, { shouldDirty: true });
    setValue('locationLng', next.coords?.lng, { shouldDirty: true });
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
          <Button variant="secondary" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmitForm)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Schedule'}
          </Button>
        </>
      }
    >
      <form
        autoComplete="off"
        onSubmit={handleSubmit(onSubmitForm)}
        className="grid grid-cols-1 gap-4 sm:grid-cols-2"
      >
        <div className="sm:col-span-2">
          <Label htmlFor="sa-job">Job</Label>
          <Select
            id="sa-job"
            {...register('jobId')}
            disabled={isLoadingJobs || isJobsError}
          >
            {/* The placeholder carries the state, so a picker that cannot fill
                never looks like one you simply have not opened yet. */}
            <option value="">
              {isLoadingJobs
                ? 'Loading jobs…'
                : isJobsError
                  ? 'Jobs unavailable'
                  : 'Select a job…'}
            </option>
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
          {/*
            Three distinct empty states, in priority order. Previously all three
            rendered as the same silent placeholder plus a "no open jobs yet"
            line that was a guess: a failed or refused request looked exactly
            like a tenant with nothing scheduled, which is how "the Job dropdown
            shows no options" became a bug report with no way to act on it.
          */}
          {isJobsError ? (
            <p className="mt-1 text-[12px] text-destructive">
              We could not load your jobs, so an appointment cannot be attached to
              one yet. Reload the page, or open Jobs to check your access.
            </p>
          ) : isLoadingJobs ? (
            <p className="mt-1 text-[12px] text-muted-soft">Loading your jobs…</p>
          ) : (
            jobs.length === 0 && (
              <p className="mt-1 text-[12px] text-muted-soft">
                No open jobs yet — move a pipeline card to spawn one, or create a
                job first.
              </p>
            )
          )}
        </div>
        {/* See ScheduleVisitModal for why this field matters: without it every
            appointment is assigned to whoever created it, and a clinical user
            never acquires a patient. */}
        <div className="sm:col-span-2">
          <Label htmlFor="sa-assignee">Assign to</Label>
          <Select id="sa-assignee" {...register('assignedRep')} disabled={staff.isLoading}>
            <option value="">— Me —</option>
            {staff.options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
          {errors.assignedRep && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.assignedRep.message}
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
          <Select
            id="sa-type"
            {...register('appointmentType', {
              // Switching away from in-person DROPS the coordinates. Keeping
              // them would leave a video call pinned to the building the visit
              // was going to be at — a fix the label no longer names, and one
              // no later reader could tell from a real one.
              onChange: (event) => {
                if (event.target.value === AppointmentType.InPerson) return;
                setValue('locationLat', undefined, { shouldDirty: true });
                setValue('locationLng', undefined, { shouldDirty: true });
              },
            })}
          >
            {APPOINTMENT_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
        {isInPerson ? (
          <LocationField
            id="sa-location"
            label="Location"
            value={location}
            onChange={setLocation}
            placeholder="Search or drop a pin"
          />
        ) : (
          <div>
            <Label htmlFor="sa-location">Location</Label>
            <Input
              id="sa-location"
              {...register('location')}
              placeholder="Meeting link or number"
            />
          </div>
        )}
      </form>
    </Modal>
  );
}

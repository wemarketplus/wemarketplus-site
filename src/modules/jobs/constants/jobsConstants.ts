import type { PillProps } from '@/shared/ui/data-display';
import { JobPriority, JobStatus, JobType } from '../types/jobsTypes';

export const JOBS_TAGS = {
  List: 'Jobs.List',
  Detail: 'Jobs.Detail',
} as const;

export const JOB_TYPE_LABELS: Record<JobType, string> = {
  [JobType.AssessmentVisit]: 'Assessment visit',
  [JobType.InService]: 'In-service',
  [JobType.FollowUp]: 'Follow-up',
  [JobType.DropIn]: 'Drop-in',
  [JobType.Presentation]: 'Presentation',
  [JobType.Paperwork]: 'Paperwork',
};

export const JOB_STATUS_LABELS: Record<JobStatus, string> = {
  [JobStatus.Open]: 'Open',
  [JobStatus.Scheduled]: 'Scheduled',
  [JobStatus.InProgress]: 'In progress',
  [JobStatus.Completed]: 'Completed',
  [JobStatus.Cancelled]: 'Cancelled',
};

export const JOB_STATUS_PILL: Record<JobStatus, PillProps['tone']> = {
  [JobStatus.Open]: 'b',
  [JobStatus.Scheduled]: 'y',
  [JobStatus.InProgress]: 'y',
  [JobStatus.Completed]: 'g',
  [JobStatus.Cancelled]: 'r',
};

export const JOB_PRIORITY_LABELS: Record<JobPriority, string> = {
  [JobPriority.Low]: 'Low',
  [JobPriority.Normal]: 'Normal',
  [JobPriority.High]: 'High',
};

export const JOB_PRIORITY_PILL: Record<JobPriority, PillProps['tone']> = {
  [JobPriority.Low]: 'b',
  [JobPriority.Normal]: 'y',
  [JobPriority.High]: 'r',
};

export const JOB_STATUS_CHIPS: ReadonlyArray<{
  value: JobStatus | 'all';
  label: string;
}> = [
  { value: 'all', label: 'All statuses' },
  ...Object.values(JobStatus).map((value) => ({
    value,
    label: JOB_STATUS_LABELS[value],
  })),
];

export const JOB_TYPE_OPTIONS: ReadonlyArray<{ value: JobType; label: string }> =
  Object.values(JobType).map((value) => ({
    value,
    label: JOB_TYPE_LABELS[value],
  }));

export const JOB_STATUS_OPTIONS: ReadonlyArray<{
  value: JobStatus;
  label: string;
}> = Object.values(JobStatus).map((value) => ({
  value,
  label: JOB_STATUS_LABELS[value],
}));

export const JOB_PRIORITY_OPTIONS: ReadonlyArray<{
  value: JobPriority;
  label: string;
}> = Object.values(JobPriority).map((value) => ({
  value,
  label: JOB_PRIORITY_LABELS[value],
}));

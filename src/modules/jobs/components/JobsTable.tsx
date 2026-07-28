import { Bot } from 'lucide-react';
import { STAGE_LABELS } from '@/modules/prospects/constants/prospectsConstants';
import { Select } from '@/shared/ui/core';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { cn } from '@/shared/utils/cn';
import {
  JOB_PRIORITY_LABELS,
  JOB_PRIORITY_PILL,
  JOB_STATUS_LABELS,
  JOB_STATUS_OPTIONS,
  JOB_STATUS_PILL,
  JOB_TYPE_LABELS,
} from '../constants/jobsConstants';
import type { JobRecord, JobStatus } from '../types/jobsTypes';
import { isAutomated, isOverdue } from '../utils/jobsUtils';

interface JobsTableProps {
  items: readonly JobRecord[];
  isBusy: boolean;
  onStatusChange: (job: JobRecord, status: JobStatus) => void;
}

export function JobsTable({ items, isBusy, onStatusChange }: JobsTableProps) {
  const columns: ReadonlyArray<Column<JobRecord>> = [
    {
      key: 'job',
      header: 'Job',
      cell: (job) => (
        <div>
          <p className="flex items-center gap-1.5 font-bold text-foreground">
            {JOB_TYPE_LABELS[job.jobType]}
            {/* A stage transition spawned this one, not a person. */}
            {isAutomated(job) && (
              <span
                title={`Auto-created when the pipeline entered "${
                  job.triggerStage ? STAGE_LABELS[job.triggerStage] : ''
                }"`}
              >
                <Bot className="h-3.5 w-3.5 text-muted-soft" />
              </span>
            )}
          </p>
          {job.objective && (
            <p className="truncate text-[11px] text-muted">{job.objective}</p>
          )}
        </div>
      ),
    },
    {
      key: 'priority',
      header: 'Priority',
      cell: (job) => (
        <Pill tone={JOB_PRIORITY_PILL[job.priority]}>
          {JOB_PRIORITY_LABELS[job.priority]}
        </Pill>
      ),
    },
    {
      key: 'due',
      header: 'Due',
      cell: (job) =>
        job.dueDate ? (
          <span
            className={cn(isOverdue(job) && 'font-semibold text-destructive')}
          >
            {formatDate(job.dueDate)}
          </span>
        ) : (
          '—'
        ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (job) => (
        <Pill tone={JOB_STATUS_PILL[job.status]}>
          {JOB_STATUS_LABELS[job.status]}
        </Pill>
      ),
    },
    {
      key: 'advance',
      header: '',
      cell: (job) => (
        <Select
          aria-label="Change job status"
          value={job.status}
          disabled={isBusy}
          onChange={(event) =>
            onStatusChange(job, event.target.value as JobStatus)
          }
        >
          {JOB_STATUS_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={items}
      rowKey={(job) => job.id}
      empty="No jobs match your filters."
    />
  );
}

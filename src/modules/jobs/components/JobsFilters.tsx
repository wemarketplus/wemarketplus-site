import { Select } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { JOB_STATUS_CHIPS, JOB_TYPE_OPTIONS } from '../constants/jobsConstants';
import type { JobStatus, JobType } from '../types/jobsTypes';

interface JobsFiltersProps {
  statusFilter: JobStatus | 'all';
  typeFilter: JobType | 'all';
  onStatus: (value: JobStatus | 'all') => void;
  onType: (value: JobType | 'all') => void;
}

export function JobsFilters({
  statusFilter,
  typeFilter,
  onStatus,
  onType,
}: JobsFiltersProps) {
  return (
    <div className="space-y-3">
      <label className="flex w-fit items-center gap-2 text-xs text-muted">
        Type
        <Select
          value={typeFilter}
          onChange={(event) => onType(event.target.value as JobType | 'all')}
        >
          <option value="all">Any type</option>
          {JOB_TYPE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
      </label>
      <div className="flex flex-wrap gap-1.5">
        {JOB_STATUS_CHIPS.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => onStatus(chip.value)}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              statusFilter === chip.value
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
            )}
          >
            {chip.label}
          </button>
        ))}
      </div>
    </div>
  );
}

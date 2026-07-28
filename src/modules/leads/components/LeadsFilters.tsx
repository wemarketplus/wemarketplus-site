import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import {
  LEAD_SOURCE_OPTIONS,
  LEAD_STATUS_CHIPS,
} from '../constants/leadsConstants';
import type { LeadSourceType, LeadStatus } from '../types/leadsTypes';

interface LeadsFiltersProps {
  search: string;
  statusFilter: LeadStatus | 'all';
  sourceFilter: LeadSourceType | 'all';
  onSearch: (value: string) => void;
  onStatus: (value: LeadStatus | 'all') => void;
  onSource: (value: LeadSourceType | 'all') => void;
}

export function LeadsFilters({
  search,
  statusFilter,
  sourceFilter,
  onSearch,
  onStatus,
  onSource,
}: LeadsFiltersProps) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <Input
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="Search patient, referrer, organisation…"
            className="pl-9"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-muted">
          Source
          <Select
            value={sourceFilter}
            onChange={(event) =>
              onSource(event.target.value as LeadSourceType | 'all')
            }
          >
            <option value="all">Any source</option>
            {LEAD_SOURCE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </label>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {LEAD_STATUS_CHIPS.map((chip) => (
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

import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
import type { EntitySelectOption } from '@/shared/ui/entity';

interface ClinicalFiltersProps {
  search: string;
  status: string;
  statusOptions: readonly EntitySelectOption[];
  searchPlaceholder: string;
  searchLabel: string;
  statusAllLabel: string;
  onSearch: (value: string) => void;
  onStatus: (value: string) => void;
}

// Shared search box + status select for the clinical tables. The backend list
// endpoints only accept pagination, so both narrow the current page client-side.
export function ClinicalFilters({
  search,
  status,
  statusOptions,
  searchPlaceholder,
  searchLabel,
  statusAllLabel,
  onSearch,
  onStatus,
}: ClinicalFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <div className="relative sm:max-w-sm sm:flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder={searchPlaceholder}
          className="pl-9"
          aria-label={searchLabel}
        />
      </div>
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value)}
        aria-label="Filter by status"
        className="sm:w-48"
      >
        <option value="">{statusAllLabel}</option>
        {statusOptions.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

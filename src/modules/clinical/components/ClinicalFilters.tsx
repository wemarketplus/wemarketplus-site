import { Select, SearchInput } from '@/shared/ui/core';
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
      <SearchInput
        wrapperClassName="sm:max-w-sm sm:flex-1"
        value={search}
        onChange={onSearch}
        placeholder={searchPlaceholder}
        aria-label={searchLabel}
      />
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

import { Select, SearchInput } from '@/shared/ui/core';
import type { EntitySelectOption } from '@/shared/ui/entity';

interface OpsFiltersProps {
  search: string;
  status: string;
  statusOptions: readonly EntitySelectOption[];
  onSearch: (value: string) => void;
  onStatus: (value: string) => void;
}

export function OpsFilters({
  search,
  status,
  statusOptions,
  onSearch,
  onStatus,
}: OpsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <SearchInput
        wrapperClassName="sm:max-w-sm sm:flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search…"
        aria-label="Search"
      />
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value)}
        aria-label="Filter by status"
        className="sm:w-48"
      >
        <option value="">All statuses</option>
        {statusOptions.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

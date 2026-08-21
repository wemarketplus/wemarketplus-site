import { Select, SearchInput } from '@/shared/ui/core';
import { TOUR_STATUS_OPTIONS } from '../constants/clToursConstants';

interface ToursFiltersProps {
  search: string;
  status: string;
  onSearch: (value: string) => void;
  onStatus: (value: string) => void;
}

export function ToursFilters({ search, status, onSearch, onStatus }: ToursFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <SearchInput
        wrapperClassName="sm:max-w-sm sm:flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search tours…"
        aria-label="Search tours"
      />
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value)}
        aria-label="Filter by status"
        className="sm:w-48"
      >
        <option value="">All statuses</option>
        {TOUR_STATUS_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

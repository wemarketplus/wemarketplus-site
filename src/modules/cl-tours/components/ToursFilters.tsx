import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
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
      <div className="relative sm:max-w-sm sm:flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search tours…"
          className="pl-9"
          aria-label="Search tours"
        />
      </div>
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

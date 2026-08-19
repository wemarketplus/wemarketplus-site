import { Input, Select, SearchInput } from '@/shared/ui/core';
import { LOCATION_STATUS_FILTER_OPTIONS } from '../constants/locationsConstants';

interface LocationsFiltersProps {
  // Server-side search (backend GET /locations?search matches locationName).
  search: string;
  onSearch: (value: string) => void;
  // Server-side status filter (backend GET /locations?status).
  status: string;
  onStatus: (value: string) => void;
  // Server-side state filter (backend GET /locations?state).
  state: string;
  onState: (value: string) => void;
}

export function LocationsFilters({
  search,
  onSearch,
  status,
  onStatus,
  state,
  onState,
}: LocationsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <SearchInput
        wrapperClassName="max-w-sm flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search by location name…"
      />
      <Select value={status} onChange={(e) => onStatus(e.target.value)} className="max-w-[12rem]">
        {LOCATION_STATUS_FILTER_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
      <Input
        value={state}
        onChange={(e) => onState(e.target.value)}
        placeholder="Filter by state"
        className="max-w-[10rem]"
      />
    </div>
  );
}

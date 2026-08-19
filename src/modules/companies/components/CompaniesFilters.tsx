import { SearchInput, Select } from '@/shared/ui/core';
import { COMPANY_STATUS_FILTER_OPTIONS } from '../constants/companiesConstants';

interface CompaniesFiltersProps {
  // Both filters are server-side (GET /companies?search&status).
  search: string;
  onSearch: (value: string) => void;
  status: string;
  onStatus: (value: string) => void;
}

export function CompaniesFilters({
  search,
  onSearch,
  status,
  onStatus,
}: CompaniesFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <div className="max-w-sm flex-1">
        <SearchInput
          value={search}
          onChange={onSearch}
          placeholder="Search by name, contact, or domain…"
        />
      </div>
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value)}
        className="max-w-xs"
        aria-label="Filter by status"
      >
        {COMPANY_STATUS_FILTER_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

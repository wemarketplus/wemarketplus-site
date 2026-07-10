import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
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
      <div className="relative max-w-sm flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by name, contact, or domain…"
          className="pl-9"
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

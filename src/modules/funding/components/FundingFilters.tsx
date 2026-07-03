import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
import { FUNDING_STATUS_LABELS, FUNDING_STATUS, type FundingStatus } from '../constants/fundingConstants';

interface FundingFiltersProps {
  // Server-side search (backend matches opportunityName).
  search: string;
  onSearch: (value: string) => void;
  // Server-side status filter (backend GET /funding?status).
  status: FundingStatus | '';
  onStatus: (value: FundingStatus | '') => void;
}

export function FundingFilters({ search, onSearch, status, onStatus }: FundingFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <div className="relative max-w-sm flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by opportunity name…"
          className="pl-9"
        />
      </div>
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value as FundingStatus | '')}
        className="max-w-xs"
      >
        <option value="">All statuses</option>
        {Object.values(FUNDING_STATUS).map((v) => (
          <option key={v} value={v}>
            {FUNDING_STATUS_LABELS[v]}
          </option>
        ))}
      </Select>
    </div>
  );
}

import { Select, SearchInput } from '@/shared/ui/core';
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
      <SearchInput
        wrapperClassName="max-w-sm flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search by opportunity name…"
      />
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

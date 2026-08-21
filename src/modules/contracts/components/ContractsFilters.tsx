import { Select, SearchInput } from '@/shared/ui/core';
import { CONTRACT_STATUS_OPTIONS } from '../constants/contractsConstants';

interface ContractsFiltersProps {
  // Client-side search across company / contract number / type.
  search: string;
  onSearch: (value: string) => void;
  // Client-side status filter (the backend GET /contracts has no filters).
  status: string;
  onStatus: (value: string) => void;
}

export function ContractsFilters({ search, onSearch, status, onStatus }: ContractsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <SearchInput
        wrapperClassName="max-w-sm flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search by company or contract number…"
      />
      <Select value={status} onChange={(e) => onStatus(e.target.value)} className="max-w-xs">
        <option value="">All statuses</option>
        {CONTRACT_STATUS_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

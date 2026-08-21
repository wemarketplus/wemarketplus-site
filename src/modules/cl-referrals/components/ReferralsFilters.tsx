import { Select, SearchInput } from '@/shared/ui/core';
import { REFERRAL_TYPE_OPTIONS } from '../constants/clReferralsConstants';

interface ReferralsFiltersProps {
  search: string;
  type: string;
  onSearch: (value: string) => void;
  onType: (value: string) => void;
}

// Search box + type select for the referral-partners list.
export function ReferralsFilters({ search, type, onSearch, onType }: ReferralsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <SearchInput
        wrapperClassName="sm:max-w-sm sm:flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search partners…"
        aria-label="Search referral partners"
      />
      <Select
        value={type}
        onChange={(e) => onType(e.target.value)}
        aria-label="Filter by type"
        className="sm:w-48"
      >
        <option value="">All types</option>
        {REFERRAL_TYPE_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

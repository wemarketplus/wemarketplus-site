import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
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
      <div className="relative sm:max-w-sm sm:flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search partners…"
          className="pl-9"
          aria-label="Search referral partners"
        />
      </div>
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

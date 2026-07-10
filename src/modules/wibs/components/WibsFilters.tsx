import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
import { WIB_STATUS, WIB_STATUS_LABELS, type WibStatus } from '../constants/wibsConstants';

interface WibsFiltersProps {
  // Server-side search (backend matches name/email/phone/state/notes).
  search: string;
  onSearch: (value: string) => void;
  // Server-side status filter (backend GET /wibs?status).
  status: WibStatus | '';
  onStatus: (value: WibStatus | '') => void;
}

export function WibsFilters({ search, onSearch, status, onStatus }: WibsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <div className="relative max-w-sm flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by name, email, phone, state…"
          className="pl-9"
        />
      </div>
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value as WibStatus | '')}
        className="max-w-xs"
      >
        <option value="">All statuses</option>
        {Object.values(WIB_STATUS).map((v) => (
          <option key={v} value={v}>
            {WIB_STATUS_LABELS[v]}
          </option>
        ))}
      </Select>
    </div>
  );
}

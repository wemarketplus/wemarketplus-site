import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
import { CONTACT_RECORD_TYPE_OPTIONS } from '../constants/contactsConstants';

interface ContactsFiltersProps {
  // Client-side search across name/email/title.
  search: string;
  onSearch: (value: string) => void;
  // Server-side recordType filter (backend GET /contacts?recordType).
  recordType: string;
  onRecordType: (value: string) => void;
}

export function ContactsFilters({
  search,
  onSearch,
  recordType,
  onRecordType,
}: ContactsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <div className="relative max-w-sm flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by name, email, or title…"
          className="pl-9"
        />
      </div>
      {/*
        A picker, not a text box: the filter is compared against the stored value,
        which is a machine string (`funding_opportunity`). Typing the label a user
        would actually think of matched nothing.
      */}
      <Select
        value={recordType}
        onChange={(e) => onRecordType(e.target.value)}
        aria-label="Filter by record type"
        className="max-w-xs"
      >
        <option value="">All record types</option>
        {CONTACT_RECORD_TYPE_OPTIONS.filter((o) => o.value).map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

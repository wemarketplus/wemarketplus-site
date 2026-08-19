import { Select, SearchInput } from '@/shared/ui/core';
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
      <SearchInput
        wrapperClassName="max-w-sm flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search by name, email, or title…"
      />
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

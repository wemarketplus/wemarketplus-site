import { Search } from 'lucide-react';
import { Input } from '@/shared/ui/core';

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
      <Input
        value={recordType}
        onChange={(e) => onRecordType(e.target.value)}
        placeholder="Filter by record type"
        className="max-w-xs"
      />
    </div>
  );
}

import { Search } from 'lucide-react';
import { Input, Select } from '@/shared/ui/core';
import { INVOICE_STATUS_OPTIONS, type InvoiceStatus } from '../constants/invoicesConstants';

interface InvoicesFiltersProps {
  // Client-side search across company / invoice number / fee model.
  search: string;
  onSearch: (value: string) => void;
  // Server-side status filter (backend GET /invoices?status).
  status: InvoiceStatus | '';
  onStatus: (value: InvoiceStatus | '') => void;
}

export function InvoicesFilters({ search, onSearch, status, onStatus }: InvoicesFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <div className="relative max-w-sm flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by company or invoice number…"
          className="pl-9"
        />
      </div>
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value as InvoiceStatus | '')}
        className="max-w-xs"
      >
        <option value="">All statuses</option>
        {INVOICE_STATUS_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}

import { Select, SearchInput } from '@/shared/ui/core';
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
      <SearchInput
        wrapperClassName="max-w-sm flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search by company or invoice number…"
      />
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

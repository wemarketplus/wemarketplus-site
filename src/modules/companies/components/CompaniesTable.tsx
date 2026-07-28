import { Building2 } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column, type DataTableSelection } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { COMPANY_STATUS_LABELS, COMPANY_STATUS_PILL } from '../constants/companiesConstants';
import type { CompanyRecord } from '../types/companiesTypes';

interface CompaniesTableProps {
  companies: readonly CompanyRecord[];
  isMutating: boolean;
  onEdit: (company: CompanyRecord) => void;
  onDelete: (company: CompanyRecord) => void;
  // Optional multi-select — passed through to DataTable. Omit for no selection.
  selection?: DataTableSelection;
  // Add handler for the first-run empty state (omit for read-only roles).
  onAdd?: () => void;
  // True when a search/status filter is active — swaps the empty copy from
  // "get started" to "no matches" so the CTA is not misleading.
  hasFilters?: boolean;
}

export function CompaniesTable({
  companies,
  isMutating,
  onEdit,
  onDelete,
  selection,
  onAdd,
  hasFilters,
}: CompaniesTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<CompanyRecord>> = [
    {
      key: 'company',
      header: 'Company',
      cell: (c) => (
        <div>
          <p className="font-bold text-foreground">{c.companyName}</p>
          {c.industry && <p className="text-[11px] text-muted">{c.industry}</p>}
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (c) => (
        <Pill tone={COMPANY_STATUS_PILL[c.status]}>{COMPANY_STATUS_LABELS[c.status]}</Pill>
      ),
    },
    {
      key: 'contact',
      header: 'Primary contact',
      cell: (c) =>
        c.primaryContactName ? (
          <div>
            <p className="text-foreground">{c.primaryContactName}</p>
            {c.primaryContactEmail && (
              <p className="text-[11px] text-muted">{c.primaryContactEmail}</p>
            )}
          </div>
        ) : (
          '—'
        ),
    },
    {
      key: 'employees',
      header: 'Employees',
      cell: (c) => (c.employeeCountTotal ?? '—'),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (c) => (
        <EntityRowActions
          onEdit={() => onEdit(c)}
          onDelete={canDelete ? () => onDelete(c) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${c.companyName}`}
          deleteLabel={`Delete ${c.companyName}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={companies}
      rowKey={(c) => c.id}
      empty={
        hasFilters ? (
          'No companies match the current filters.'
        ) : (
          <EmptyState
            icon={Building2}
            title="No companies yet"
            description="Add the employer companies you work with to organize contacts and track relationships."
            actionLabel={onAdd ? 'Add company' : undefined}
            onAction={onAdd}
          />
        )
      }
      selection={selection}
    />
  );
}

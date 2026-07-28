import { Contact } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column, type DataTableSelection } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { ContactRecord } from '../types/contactsTypes';

interface ContactsTableProps {
  contacts: readonly ContactRecord[];
  isMutating: boolean;
  onEdit: (contact: ContactRecord) => void;
  onDelete: (contact: ContactRecord) => void;
  // Optional multi-select — passed through to DataTable. Omit for no selection.
  selection?: DataTableSelection;
  // Add handler for the first-run empty state (omit for read-only roles).
  onAdd?: () => void;
  // True when a search/filter is active — swaps the empty copy from "get
  // started" to "no matches" so the CTA is not misleading.
  hasFilters?: boolean;
}

export function ContactsTable({
  contacts,
  isMutating,
  onEdit,
  onDelete,
  selection,
  onAdd,
  hasFilters,
}: ContactsTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ContactRecord>> = [
    {
      key: 'contact',
      header: 'Contact',
      cell: (c) => (
        <div>
          <p className="font-bold text-foreground">{c.name}</p>
          {c.title && <p className="text-[11px] text-muted">{c.title}</p>}
        </div>
      ),
    },
    { key: 'email', header: 'Email', cell: (c) => c.email ?? '—' },
    { key: 'phone', header: 'Phone', cell: (c) => c.phone ?? '—' },
    {
      key: 'record',
      header: 'Attached to',
      cell: (c) => (c.recordType ? c.recordType : '—'),
    },
    { key: 'created', header: 'Added', cell: (c) => formatDate(c.createdAt) },
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
          editLabel={`Edit ${c.name}`}
          deleteLabel={`Delete ${c.name}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={contacts}
      rowKey={(c) => c.id}
      empty={
        hasFilters ? (
          'No contacts match the current filters.'
        ) : (
          <EmptyState
            icon={Contact}
            title="No contacts yet"
            description="Contacts are the people behind every record. Add your first to start building your book of business."
            actionLabel={onAdd ? 'Add contact' : undefined}
            onAction={onAdd}
          />
        )
      }
      selection={selection}
    />
  );
}

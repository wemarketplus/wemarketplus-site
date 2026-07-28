import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { DocumentRecord } from '../types/documentsTypes';

interface DocumentsTableProps {
  documents: readonly DocumentRecord[];
  isMutating: boolean;
  onDelete: (doc: DocumentRecord) => void;
  empty: string;
}

export function DocumentsTable({ documents, isMutating, onDelete, empty }: DocumentsTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  // There is no update endpoint, so no edit action is offered.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<DocumentRecord>> = [
    {
      key: 'file',
      header: 'File',
      cell: (d) => (
        <div>
          <a
            href={d.driveUrl}
            target="_blank"
            rel="noreferrer"
            className="font-bold text-azure underline"
          >
            {d.fileName}
          </a>
          {d.mimeType && <p className="text-[11px] text-muted">{d.mimeType}</p>}
        </div>
      ),
    },
    { key: 'type', header: 'Type', cell: (d) => d.documentType || '—' },
    { key: 'notes', header: 'Notes', cell: (d) => d.notes ?? '—' },
    { key: 'created', header: 'Added', cell: (d) => formatDate(d.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-16',
      className: 'text-right',
      cell: (d) => (
        <EntityRowActions
          onDelete={canDelete ? () => onDelete(d) : undefined}
          disabled={isMutating}
          deleteLabel={`Delete ${d.fileName}`}
        />
      ),
    },
  ];

  return (
    <DataTable columns={columns} rows={documents} rowKey={(d) => d.id} empty={empty} />
  );
}

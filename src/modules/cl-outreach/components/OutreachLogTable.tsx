import { MapPin } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { visitTypeLabel } from '../constants/clOutreachConstants';
import type { ClOutreachVisitRecord } from '../types/clOutreachApiTypes';

interface OutreachLogTableProps {
  visits: readonly ClOutreachVisitRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (visit: ClOutreachVisitRecord) => void;
  onDelete: (visit: ClOutreachVisitRecord) => void;
  onAdd?: () => void;
}

export function OutreachLogTable({
  visits,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onAdd,
}: OutreachLogTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ClOutreachVisitRecord>> = [
    { key: 'date', header: 'Date', cell: (v) => formatDate(v.visitDate) },
    {
      key: 'contact',
      header: 'Contact',
      cell: (v) => <span className="font-bold text-[#111]">{v.contactName ?? '—'}</span>,
    },
    { key: 'location', header: 'Location', cell: (v) => v.locationName ?? '—' },
    {
      key: 'type',
      header: 'Type',
      cell: (v) => (v.visitType ? <Pill tone="b">{visitTypeLabel(v.visitType)}</Pill> : '—'),
    },
    {
      key: 'miles',
      header: 'Miles',
      cell: (v) => (v.miles != null ? `${Number(v.miles).toFixed(1)} mi` : '—'),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (v) => (
        <EntityRowActions
          onEdit={() => onEdit(v)}
          onDelete={canDelete ? () => onDelete(v) : undefined}
          disabled={isMutating}
          editLabel="Edit visit"
          deleteLabel="Delete visit"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={visits}
      rowKey={(v) => v.id}
      empty={
        hasFilters ? (
          'No visits match the current filters.'
        ) : (
          <EmptyState
            icon={MapPin}
            title="No outreach logged yet"
            description="Log a field visit to a referral source to build your outreach history and mileage."
            actionLabel={onAdd ? 'Log visit' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}

import { Heart, MapPin } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { Button } from '@/shared/ui/core';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { REFERRAL_TYPE_PILL, referralTypeLabel } from '../constants/clReferralsConstants';
import type { ClReferralSourceRecord } from '../types/clReferralsApiTypes';

interface ClReferralsTableProps {
  items: readonly ClReferralSourceRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (source: ClReferralSourceRecord) => void;
  onDelete: (source: ClReferralSourceRecord) => void;
  onLogVisit: (source: ClReferralSourceRecord) => void;
  onAdd?: () => void;
}

export function ClReferralsTable({
  items,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onLogVisit,
  onAdd,
}: ClReferralsTableProps) {
  // Delete is Admin/Owner-only on the backend for most CRUD; mirror that gate.
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClReferralSourceRecord>> = [
    {
      key: 'name',
      header: 'Name',
      cell: (r) => (
        <div>
          <p className="font-bold text-foreground">{r.name}</p>
          <p className="text-[11px] text-muted">{r.email ?? r.phone ?? '—'}</p>
        </div>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      cell: (r) =>
        r.type ? (
          <Pill tone={REFERRAL_TYPE_PILL[r.type] ?? 'b'}>{referralTypeLabel(r.type)}</Pill>
        ) : (
          '—'
        ),
    },
    { key: 'organization', header: 'Organization', cell: (r) => r.organization ?? '—' },
    {
      key: 'leadsSent',
      header: 'Leads sent',
      cell: (r) => <span className="font-semibold text-foreground">{r.referralCount}</span>,
    },
    {
      key: 'lastContact',
      header: 'Last contact',
      cell: (r) => (r.lastReferralDate ? formatDate(r.lastReferralDate) : '—'),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-44',
      className: 'text-right',
      cell: (r) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => onLogVisit(r)}
            disabled={isMutating}
            aria-label={`Log visit to ${r.name}`}
          >
            <MapPin className="h-3.5 w-3.5" /> Log visit
          </Button>
          <EntityRowActions
            onEdit={() => onEdit(r)}
            onDelete={canDelete ? () => onDelete(r) : undefined}
            disabled={isMutating}
            editLabel={`Edit ${r.name}`}
            deleteLabel={`Delete ${r.name}`}
          />
        </div>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={items}
      rowKey={(r) => r.id}
      empty={
        hasFilters ? (
          'No referral partners match the current filters.'
        ) : (
          <EmptyState
            icon={Heart}
            title="No referral partners yet"
            description="Add the physicians, hospitals, social workers, and community contacts who feed your pipeline."
            actionLabel={onAdd ? 'Add source' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}

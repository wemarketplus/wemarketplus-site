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
      /**
       * The partner's NAME, and nothing else.
       *
       * This cell used to print `email ?? phone ?? '—'` on a second line under
       * the name. Three things were wrong with it. The column is headed "Name",
       * so a contact address under it reads as part of the name rather than as a
       * separate fact. It was inconsistent — whichever of the two happened to be
       * stored appeared, so one row showed an address and the next a phone
       * number with nothing saying which. And it put an email in front of
       * everyone with list access on a screen that only needs to identify the
       * partner; the address is on the record, which is where someone who
       * actually needs to contact them looks.
       *
       * Organization is already its own column, so nothing that identifies the
       * partner was lost. Edit (in the row actions) is where email and phone are
       * read and written.
       */
      key: 'name',
      header: 'Name',
      cell: (r) => <span className="font-bold text-foreground">{r.name}</span>,
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
      /**
       * CITY. The add/edit form has always asked for it — REFERRAL_FIELDS labels
       * the `address` column "City" — and the backend has always stored it, but
       * no column rendered it, so the one fact that says WHERE a partner is was
       * write-only. It also made the value look unsaveable: someone editing a
       * partner's city had nowhere to confirm the change had taken, which is how
       * "City cannot be updated" gets reported against a PATCH that works.
       *
       * Reads `address` rather than a `city` field because that IS the column
       * behind the form's City input (cl_referral_sources has no separate city);
       * renaming the column is a migration this does not need.
       *
       * Placed next to Organization — the other "who/where is this partner"
       * fact — rather than at the end of the row, and left-aligned like every
       * other text cell so the column reads down cleanly.
       */
      key: 'city',
      header: 'City',
      cell: (r) => r.address ?? '—',
    },
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

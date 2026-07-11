import { Users } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  CARE_LEVEL_LABELS,
  LEAD_STAGE_LABELS,
  STAGE_OPTIONS,
  STAGE_PILL,
  URGENCY_LABELS,
  URGENCY_PILL,
} from '../constants/leadsConstants';
import { leadName } from '../utils/leadsUtils';
import type { ClLeadRecord } from '../types/clLeadApiTypes';

interface LeadsTableProps {
  leads: readonly ClLeadRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (lead: ClLeadRecord) => void;
  onDelete: (lead: ClLeadRecord) => void;
  onStageChange: (lead: ClLeadRecord, stage: string) => void;
  onAdd?: () => void;
}

export function LeadsTable({
  leads,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStageChange,
  onAdd,
}: LeadsTableProps) {
  // Delete is Admin/Owner-only on the backend for most CRUD; mirror that gate.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ClLeadRecord>> = [
    {
      key: 'name',
      header: 'Name',
      cell: (l) => (
        <div>
          <p className="font-bold text-[#111]">{leadName(l)}</p>
          <p className="text-[11px] text-[#667]">{l.phone ?? '—'}</p>
        </div>
      ),
    },
    {
      key: 'care',
      header: 'Care level',
      cell: (l) => (l.careLevel ? CARE_LEVEL_LABELS[l.careLevel] : '—'),
    },
    {
      key: 'stage',
      header: 'Status',
      cell: (l) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={STAGE_PILL[l.stage]}>{LEAD_STAGE_LABELS[l.stage]}</Pill>
          <select
            aria-label={`Change stage for ${leadName(l)}`}
            value={l.stage}
            disabled={isMutating}
            onChange={(e) => onStageChange(l, e.target.value)}
            className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
          >
            {STAGE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ),
    },
    {
      key: 'urgency',
      header: 'Urgency',
      cell: (l) => <Pill tone={URGENCY_PILL[l.urgency]}>{URGENCY_LABELS[l.urgency]}</Pill>,
    },
    { key: 'source', header: 'Source', cell: (l) => l.source ?? '—' },
    {
      key: 'followUp',
      header: 'Follow-up',
      cell: (l) => (l.followUpDate ? formatDate(l.followUpDate) : '—'),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (l) => (
        <EntityRowActions
          onEdit={() => onEdit(l)}
          onDelete={canDelete ? () => onDelete(l) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${leadName(l)}`}
          deleteLabel={`Delete ${leadName(l)}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={leads}
      rowKey={(l) => l.id}
      empty={
        hasFilters ? (
          'No leads match the current filters.'
        ) : (
          <EmptyState
            icon={Users}
            title="No leads yet"
            description="Add your first prospective resident to start building the senior-living pipeline."
            actionLabel={onAdd ? 'Add lead' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}

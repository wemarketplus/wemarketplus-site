import { Users } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, StatusSelect, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  CARE_LEVEL_LABELS,
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
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClLeadRecord>> = [
    {
      key: 'name',
      header: 'Name',
      // NAME ONLY. This cell used to print the lead's phone number on a second
      // line under the name, in a column headed "Name" and with no contact
      // column anywhere in the table to explain it. Three things were wrong
      // with it: the pipeline is a scanning view (who is in play, at what stage)
      // and a phone number is not what you scan by; the number appeared under
      // a heading that does not claim to show it; and for the many leads with
      // no phone on file it rendered a bare em dash under every name, so the
      // rows carried a column of placeholders for a field nobody asked to see.
      // Phone is still captured and edited on the lead form (LEAD_FIELDS), and
      // that is where it belongs — one lead at a time, labelled as itself.
      cell: (l) => <p className="font-bold text-foreground">{leadName(l)}</p>,
    },
    {
      key: 'care',
      header: 'Care level',
      cell: (l) => (l.careLevel ? CARE_LEVEL_LABELS[l.careLevel] : '—'),
    },
    {
      key: 'stage',
      // "Stage", not "Status": the create/edit form labels this field Stage
      // (LEAD_FIELDS in leadsConstants) and the filter bar says "All stages", so
      // a column headed "Status" read as a different field than the one just set.
      header: 'Stage',
      // One control, not a badge beside a dropdown of the same value — see
      // StatusSelect. The PATCH behind `onStageChange` is unchanged.
      cell: (l) => (
        <StatusSelect
          value={l.stage}
          tone={STAGE_PILL[l.stage]}
          options={STAGE_OPTIONS}
          disabled={isMutating}
          onChange={(stage) => onStageChange(l, stage)}
          aria-label={`Change stage for ${leadName(l)}`}
        />
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

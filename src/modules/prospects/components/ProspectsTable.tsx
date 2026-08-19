import { UserPlus } from 'lucide-react';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { Prospect } from '@/shared/types';
import {
  PROSPECT_STATUS_LABELS,
  STATUS_PILL,
  URGENCY_LABELS,
  URGENCY_PILL,
} from '../constants/prospectsConstants';

const buildColumns = (
  onOpen: (id: string) => void,
  onEdit: (id: string) => void,
  onDelete: ((id: string) => void) | undefined,
): ReadonlyArray<Column<Prospect>> => [
  {
    key: 'prospect',
    header: 'Prospect',
    cell: (p) => (
      <button type="button" onClick={() => onOpen(p.id)} className="text-left">
        <p className="font-bold text-foreground hover:text-primary">{p.name}</p>
        <p className="text-[11px] text-muted">{p.email}</p>
      </button>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    cell: (p) => <Pill tone={STATUS_PILL[p.status]}>{PROSPECT_STATUS_LABELS[p.status]}</Pill>,
  },
  {
    // AI Referral Triage, 1-10. Null on rows created before the column had a writer —
    // shown as an em dash rather than 0, because "not scored" and "scored zero" are
    // different statements and the second one would be a lie about the referral.
    key: 'aiAdmitScore',
    header: 'Triage',
    // `?? null` covers both null (scored column, no value) and undefined (a caller
    // whose payload predates the field) with one branch.
    cell: (p) => {
      const score = p.aiAdmitScore ?? null;
      return score === null ? (
        <span className="text-muted-soft">—</span>
      ) : (
        <Pill tone={score >= 7.5 ? 'g' : score >= 5 ? 'y' : 'r'}>
          {Number(score).toFixed(1)}
        </Pill>
      );
    },
  },
  {
    key: 'urgency',
    header: 'Urgency',
    cell: (p) => <Pill tone={URGENCY_PILL[p.urgency]}>{URGENCY_LABELS[p.urgency]}</Pill>,
  },
  { key: 'source', header: 'Source', cell: (p) => p.referralSource },
  { key: 'marketer', header: 'Marketer', cell: (p) => p.assignedMarketer },
  { key: 'next', header: 'Next step', cell: (p) => p.nextStep },
  { key: 'due', header: 'Due', cell: (p) => formatDate(p.followUpDate) },
  {
    key: 'actions',
    header: '',
    headerClassName: 'w-20',
    className: 'text-right',
    cell: (p) => (
      <EntityRowActions
        onEdit={() => onEdit(p.id)}
        onDelete={onDelete ? () => onDelete(p.id) : undefined}
        editLabel={`Edit ${p.name}`}
        deleteLabel={`Delete ${p.name}`}
      />
    ),
  },
];

interface ProspectsTableProps {
  prospects: readonly Prospect[];
  // Add handler for the first-run empty state.
  onAdd?: () => void;
  // True when a search/status/urgency filter is active — swaps the empty copy
  // from "get started" to "no matches" so the CTA is not misleading.
  hasFilters?: boolean;
  /** Opens the detail drawer for a row. */
  onOpen: (id: string) => void;
  /** Opens the Edit modal, seeded from this row. */
  onEdit: (id: string) => void;
  /** Omitted (hides the action) for a caller without delete permission. */
  onDelete?: (id: string) => void;
}

export function ProspectsTable({
  prospects,
  onAdd,
  hasFilters,
  onOpen,
  onEdit,
  onDelete,
}: ProspectsTableProps) {
  return (
    <DataTable
      columns={buildColumns(onOpen, onEdit, onDelete)}
      rows={prospects}
      rowKey={(p) => p.id}
      empty={
        hasFilters ? (
          'No prospects match the current filters.'
        ) : (
          <EmptyState
            icon={UserPlus}
            title="No prospects yet"
            description="Add a lead to start tracking it through your pipeline from first touch to close."
            actionLabel={onAdd ? 'Add prospect' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}

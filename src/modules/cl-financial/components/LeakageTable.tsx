import { TrendingDown, Check, RotateCcw } from 'lucide-react';
import { CL_FINANCIAL_ROLES, CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { Button } from '@/shared/ui/core';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatUsd } from '../utils/financialFormat';
import { num } from '../utils/clFinancialMappers';
import { LEAKAGE_STATUS } from '../constants/clFinancialApiConstants';
import {
  LEAKAGE_STATUS_LABELS,
  LEAKAGE_STATUS_PILL,
  LEAKAGE_TYPE_OPTIONS,
} from '../constants/clFinancialConstants';
import type { ClLeakageItemRecord } from '../types/clFinancialApiTypes';

const TYPE_LABELS: Record<string, string> = Object.fromEntries(
  LEAKAGE_TYPE_OPTIONS.map((o) => [o.value, o.label]),
);

interface LeakageTableProps {
  items: readonly ClLeakageItemRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (l: ClLeakageItemRecord) => void;
  onDelete: (l: ClLeakageItemRecord) => void;
  onResolve: (l: ClLeakageItemRecord) => void;
  /** Puts a resolved item back on the books — see the Action column below. */
  onReopen: (l: ClLeakageItemRecord) => void;
  onAdd?: () => void;
}

// Revenue Leakage — a distinct leakage-items surface (Issue / Type / Monthly
// Impact / Status / Resolve), matching the Max demo's Revenue Leakage tab.
// Separate from the Ledger's actual-vs-budget revenue entries.
export function LeakageTable({
  items,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onResolve,
  onReopen,
  onAdd,
}: LeakageTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);
  const canResolve = isAny(CL_FINANCIAL_ROLES);

  const columns: ReadonlyArray<Column<ClLeakageItemRecord>> = [
    /**
     * The Issue cell says the ISSUE. Nothing else.
     *
     * It stacked `notes` on a second line, and Type ALREADY has its own column
     * two cells over — so an item whose note named its type ("Unbilled fee",
     * which is what people write there) printed that value twice in the same
     * row, once as a caption under the issue and once under the Type header.
     * That is the "Type information is displayed inside the Issue tab" report,
     * and the duplication is the half that made it confusing: two cells
     * disagreeing about which column owns the value.
     *
     * So the stacked line goes and Type keeps its dedicated column. Notes stay on
     * the record — collected and editable in LEAKAGE_FIELDS, and still searched
     * server-side (`searchFields: ["issue", "type", "notes"]`).
     */
    {
      key: 'issue',
      header: 'Issue',
      cell: (l) => <span className="font-bold text-foreground">{l.issue}</span>,
    },
    {
      key: 'type',
      header: 'Type',
      cell: (l) => TYPE_LABELS[l.type] ?? l.type,
    },
    {
      key: 'impact',
      header: 'Monthly impact',
      cell: (l) => (
        <span className="font-semibold text-destructive">
          -{formatUsd(num(l.monthlyImpact))}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (l) => (
        <Pill tone={LEAKAGE_STATUS_PILL[l.status]}>{LEAKAGE_STATUS_LABELS[l.status]}</Pill>
      ),
    },
    /**
     * The Action column offers the ONE transition available from the row's
     * current state. It never restates the state.
     *
     * ── What was wrong ────────────────────────────────────────────────────────
     * A resolved row printed the word "Resolved" here, one cell to the right of
     * the Status pill already reading "Resolved" — the same value twice in the
     * same row, under a header promising an action. Anything other than resolved
     * printed "Open", which is worse than redundant: "Open" is not one of this
     * resource's statuses at all (they are Active / Ongoing / Review / Fix
     * needed / Resolved), so the column invented a sixth state and showed it
     * beside the real one.
     *
     * ── What replaces it ─────────────────────────────────────────────────────
     * Resolved -> Reopen; anything else -> Resolve. That is the whole workflow,
     * and it is why the Resolve button cannot reappear on a resolved row: an
     * item is resolved once, and re-resolving it overwrote the original
     * resolvedBy/resolvedAt (the backend now refuses it outright — see
     * ClLeakageItemService.resolveWithActor). Reopening clears that stamp and
     * puts Resolve back, so a wrongly-closed item is recoverable without anyone
     * having to delete and re-enter it.
     *
     * Editing is untouched and stays available in EVERY state, including
     * resolved: correcting the impact figure on a closed item is ordinary work,
     * and it is the row-actions menu's job, not this column's.
     *
     * A role without CL_FINANCIAL_ROLES gets an em dash — the table's own idiom
     * for "nothing here" — rather than a word that duplicates the Status cell.
     */
    {
      key: 'resolve',
      header: 'Action',
      cell: (l) => {
        if (!canResolve) return <span className="text-muted-soft">—</span>;
        return l.status === LEAKAGE_STATUS.Resolved ? (
          <Button
            variant="ghost"
            size="sm"
            disabled={isMutating}
            onClick={() => onReopen(l)}
            aria-label={`Reopen ${l.issue}`}
          >
            <RotateCcw className="h-3.5 w-3.5" /> Reopen
          </Button>
        ) : (
          <Button
            variant="secondary"
            size="sm"
            disabled={isMutating}
            onClick={() => onResolve(l)}
            aria-label={`Resolve ${l.issue}`}
          >
            <Check className="h-3.5 w-3.5 text-success" /> Resolve
          </Button>
        );
      },
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
          editLabel="Edit leakage item"
          deleteLabel="Delete leakage item"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={items}
      rowKey={(l) => l.id}
      empty={
        hasFilters ? (
          'No leakage items match the current filters.'
        ) : (
          <EmptyState
            icon={TrendingDown}
            title="No revenue leakage flagged"
            description="Log a leakage item to track missed billables, concessions, and downgrades."
            actionLabel={onAdd ? 'Add leakage item' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}

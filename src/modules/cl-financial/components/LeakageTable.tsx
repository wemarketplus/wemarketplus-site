import { TrendingDown, Check } from 'lucide-react';
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
  onAdd,
}: LeakageTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);
  const canResolve = isAny(CL_FINANCIAL_ROLES);

  const columns: ReadonlyArray<Column<ClLeakageItemRecord>> = [
    {
      key: 'issue',
      header: 'Issue',
      cell: (l) => (
        <div>
          <p className="font-bold text-[#111]">{l.issue}</p>
          {l.notes && <p className="text-[11px] text-[#667]">{l.notes}</p>}
        </div>
      ),
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
    {
      key: 'resolve',
      header: 'Action',
      cell: (l) =>
        l.status !== LEAKAGE_STATUS.Resolved && canResolve ? (
          <Button
            variant="secondary"
            size="sm"
            disabled={isMutating}
            onClick={() => onResolve(l)}
            aria-label={`Resolve ${l.issue}`}
          >
            <Check className="h-3.5 w-3.5 text-success" /> Resolve
          </Button>
        ) : l.status === LEAKAGE_STATUS.Resolved ? (
          <span className="text-[11px] text-muted-soft">Resolved</span>
        ) : (
          <span className="text-[11px] text-muted-soft">Open</span>
        ),
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

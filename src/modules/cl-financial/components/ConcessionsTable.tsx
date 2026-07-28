import { BadgePercent, Check, X } from 'lucide-react';
import { CL_FINANCIAL_ROLES, CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { Button } from '@/shared/ui/core';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatUsd } from '../utils/financialFormat';
import { num } from '../utils/clFinancialMappers';
import { CONCESSION_STATUS } from '../constants/clFinancialApiConstants';
import {
  CONCESSION_STATUS_LABELS,
  CONCESSION_STATUS_PILL,
} from '../constants/clFinancialConstants';
import type { ClConcessionRecord } from '../types/clFinancialApiTypes';

interface ConcessionsTableProps {
  concessions: readonly ClConcessionRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (c: ClConcessionRecord) => void;
  onDelete: (c: ClConcessionRecord) => void;
  onDecide: (c: ClConcessionRecord, decision: 'approved' | 'rejected') => void;
  onAdd?: () => void;
}

export function ConcessionsTable({
  concessions,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onDecide,
  onAdd,
}: ConcessionsTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);
  // Approve/reject was previously ungated entirely — restrict to the same
  // role group that can reach this page (CL_FINANCIAL_ROLES).
  const canDecide = isAny(CL_FINANCIAL_ROLES);

  const columns: ReadonlyArray<Column<ClConcessionRecord>> = [
    {
      key: 'type',
      header: 'Concession',
      cell: (c) => (
        <div>
          <p className="font-bold text-foreground">{c.type}</p>
          {c.reason && <p className="text-[11px] text-muted">{c.reason}</p>}
        </div>
      ),
    },
    {
      key: 'value',
      header: 'Value',
      cell: (c) => (c.valueAmount != null ? formatUsd(num(c.valueAmount)) : '—'),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (c) => (
        <Pill tone={CONCESSION_STATUS_PILL[c.status]}>{CONCESSION_STATUS_LABELS[c.status]}</Pill>
      ),
    },
    {
      key: 'decision',
      header: 'Decision',
      cell: (c) =>
        c.status === CONCESSION_STATUS.Pending && canDecide ? (
          <div className="flex gap-1.5">
            <Button
              variant="secondary"
              size="sm"
              disabled={isMutating}
              onClick={() => onDecide(c, 'approved')}
              aria-label={`Approve ${c.type}`}
            >
              <Check className="h-3.5 w-3.5 text-success" /> Approve
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={isMutating}
              onClick={() => onDecide(c, 'rejected')}
              aria-label={`Reject ${c.type}`}
            >
              <X className="h-3.5 w-3.5 text-destructive" /> Reject
            </Button>
          </div>
        ) : c.status === CONCESSION_STATUS.Pending ? (
          <span className="text-[11px] text-muted-soft">Pending</span>
        ) : (
          <span className="text-[11px] text-muted-soft">Decided</span>
        ),
    },
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
          editLabel="Edit concession"
          deleteLabel="Delete concession"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={concessions}
      rowKey={(c) => c.id}
      empty={
        hasFilters ? (
          'No concessions match the current filters.'
        ) : (
          <EmptyState
            icon={BadgePercent}
            title="No concessions yet"
            description="Log a concession request so it can be reviewed and approved."
            actionLabel={onAdd ? 'Add concession' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}

import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { formatMoney } from '../utils/contractsUtils';
import type { ContractStatus } from '../constants/contractsConstants';
import type { ContractRecord } from '../types/contractsTypes';

interface ContractsTableProps {
  contracts: readonly ContractRecord[];
  isMutating: boolean;
  onEdit: (contract: ContractRecord) => void;
  onDelete: (contract: ContractRecord) => void;
}

const STATUS_TONE: Record<ContractStatus, PillProps['tone']> = {
  draft: 'b',
  active: 'g',
  signed: 'p',
  expired: 'y',
  terminated: 'r',
};

export function ContractsTable({ contracts, isMutating, onEdit, onDelete }: ContractsTableProps) {
  // Delete is Admin/Owner-only on the backend (@Roles); mirror that gate.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ContractRecord>> = [
    {
      key: 'contract',
      header: 'Contract',
      cell: (c) => (
        <div>
          <p className="font-bold text-[#111]">{c.companyName}</p>
          <p className="text-[11px] text-[#667]">{c.contractNumber}</p>
        </div>
      ),
    },
    { key: 'type', header: 'Type', cell: (c) => c.contractType ?? '—' },
    { key: 'value', header: 'Value', cell: (c) => formatMoney(c.value) },
    {
      key: 'status',
      header: 'Status',
      cell: (c) => <Pill tone={STATUS_TONE[c.status]}>{c.status}</Pill>,
    },
    { key: 'expiry', header: 'Expires', cell: (c) => (c.expiryDate ? formatDate(c.expiryDate) : '—') },
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
          editLabel={`Edit ${c.contractNumber}`}
          deleteLabel={`Delete ${c.contractNumber}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={contracts}
      rowKey={(c) => c.id}
      empty="No contracts match the current filters."
    />
  );
}

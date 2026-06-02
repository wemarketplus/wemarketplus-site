import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { Prospect } from '@/shared/types';
import {
  PROSPECT_STATUS_LABELS,
  STATUS_PILL,
  URGENCY_LABELS,
  URGENCY_PILL,
} from '../constants/prospectsConstants';

const columns: ReadonlyArray<Column<Prospect>> = [
  {
    key: 'prospect',
    header: 'Prospect',
    cell: (p) => (
      <div>
        <p className="font-bold text-[#111]">{p.name}</p>
        <p className="text-[11px] text-[#667]">{p.email}</p>
      </div>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    cell: (p) => <Pill tone={STATUS_PILL[p.status]}>{PROSPECT_STATUS_LABELS[p.status]}</Pill>,
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
];

export function ProspectsTable({ prospects }: { prospects: readonly Prospect[] }) {
  return (
    <DataTable
      columns={columns}
      rows={prospects}
      rowKey={(p) => p.id}
      empty="No prospects match the current filters."
    />
  );
}

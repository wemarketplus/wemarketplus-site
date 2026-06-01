import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { ApartmentStatus, type Apartment } from '@/shared/types';
import { APARTMENT_STATUS_LABEL } from '../constants/clOperationsConstants';

const STATUS_PILL: Record<ApartmentStatus, PillProps['tone']> = {
  [ApartmentStatus.Available]: 'g',
  [ApartmentStatus.Occupied]: 'b',
  [ApartmentStatus.Reserved]: 'p',
  [ApartmentStatus.OnNotice]: 'y',
  [ApartmentStatus.MakeReady]: 'y',
  [ApartmentStatus.Maintenance]: 'r',
  [ApartmentStatus.Offline]: 'b',
};

const columns: ReadonlyArray<Column<Apartment>> = [
  {
    key: 'unit',
    header: 'Unit',
    cell: (a) => <span className="font-bold text-[#111]">{a.unitNumber}</span>,
  },
  { key: 'type', header: 'Type', cell: (a) => a.unitType },
  { key: 'care', header: 'Care', cell: (a) => a.careLevel },
  {
    key: 'status',
    header: 'Status',
    cell: (a) => <Pill tone={STATUS_PILL[a.status]}>{APARTMENT_STATUS_LABEL[a.status]}</Pill>,
  },
  { key: 'resident', header: 'Resident', cell: (a) => a.residentName ?? '—' },
  { key: 'rate', header: 'Rate', cell: (a) => `$${a.monthlyRate.toLocaleString()}` },
];

export function ApartmentsTable({ apartments }: { apartments: readonly Apartment[] }) {
  return <DataTable columns={columns} rows={apartments} rowKey={(a) => a.id} />;
}

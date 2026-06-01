import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { ReferralSourceStatus, type ReferralSource } from '@/shared/types';
import { REFERRAL_STATUS_LABELS } from '../constants/referralsConstants';
import { daysSince } from '../utils/referralsUtils';

const STATUS_PILL: Record<ReferralSourceStatus, PillProps['tone']> = {
  [ReferralSourceStatus.Green]: 'g',
  [ReferralSourceStatus.Building]: 'y',
  [ReferralSourceStatus.Red]: 'r',
};

const columns: ReadonlyArray<Column<ReferralSource>> = [
  {
    key: 'contact',
    header: 'Contact',
    cell: (r) => (
      <div>
        <p className="font-bold text-[#111]">{r.fullName}</p>
        <p className="text-[11px] text-[#667]">{r.title}</p>
      </div>
    ),
  },
  { key: 'organization', header: 'Organization', cell: (r) => r.organization },
  {
    key: 'status',
    header: 'Status',
    cell: (r) => <Pill tone={STATUS_PILL[r.status]}>{REFERRAL_STATUS_LABELS[r.status]}</Pill>,
  },
  { key: 'referrals', header: 'Referrals', cell: (r) => r.referralCount },
  {
    key: 'lastTouch',
    header: 'Last touch',
    cell: (r) => `${formatDate(r.lastContactDate)} (${daysSince(r.lastContactDate)}d)`,
  },
  { key: 'nextAction', header: 'Next action', cell: (r) => r.nextAction ?? '—' },
];

export function ReferralsTable({ items }: { items: readonly ReferralSource[] }) {
  return (
    <DataTable
      columns={columns}
      rows={items}
      rowKey={(r) => r.id}
      empty="No referral sources match your filters."
    />
  );
}

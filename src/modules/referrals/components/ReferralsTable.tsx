import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import type { ReferralSource } from '@/shared/types';
import {
  REFERRAL_STATUS_LABELS,
  STATUS_PILL,
} from '../constants/referralsConstants';
import { lastTouchLabel } from '../utils/referralsUtils';

interface ReferralsTableProps {
  items: readonly ReferralSource[];
  onOpen: (id: string) => void;
}

const buildColumns = (
  onOpen: (id: string) => void,
): ReadonlyArray<Column<ReferralSource>> => [
  {
    key: 'contact',
    header: 'Account',
    cell: (r) => (
      <button
        type="button"
        onClick={() => onOpen(r.id)}
        className="text-left"
      >
        <p className="font-bold text-foreground hover:text-primary">
          {r.organization}
        </p>
        <p className="text-[11px] text-muted">{r.fullName}</p>
      </button>
    ),
  },
  {
    key: 'status',
    header: 'Status',
    cell: (r) => (
      <div className="flex flex-wrap items-center gap-1.5">
        <Pill tone={STATUS_PILL[r.status]}>
          {REFERRAL_STATUS_LABELS[r.status]}
        </Pill>
        {/* The COLD flag is a different axis from the lifecycle status above: an
            `active_referrer` nobody has visited in three weeks is still cold, and
            that is exactly the account worth surfacing. `isCold` is computed by
            the backend against the 14-day rule — never recomputed here. */}
        {r.isCold && <Pill tone="r">Cold</Pill>}
      </div>
    ),
  },
  { key: 'referrals', header: 'Referrals', cell: (r) => r.referralCount },
  {
    key: 'lastTouch',
    header: 'Last touch',
    cell: (r) => (
      <span className={r.isCold ? 'text-destructive' : undefined}>
        {lastTouchLabel(r)}
      </span>
    ),
  },
  { key: 'territory', header: 'Territory', cell: (r) => r.territoryArea ?? '—' },
];

export function ReferralsTable({ items, onOpen }: ReferralsTableProps) {
  return (
    <DataTable
      columns={buildColumns(onOpen)}
      rows={items}
      rowKey={(r) => r.id}
      empty="No referral sources match your filters."
    />
  );
}

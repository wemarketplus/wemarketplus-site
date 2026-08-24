import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import type { ReferralSource } from '@/shared/types';
import {
  REFERRAL_STATUS_LABELS,
  STATUS_PILL,
} from '../constants/referralsConstants';
import { lastTouchLabel } from '../utils/referralsUtils';

interface ReferralsTableProps {
  items: readonly ReferralSource[];
  onOpen: (id: string) => void;
  /** Opens the Edit modal, seeded from this row. */
  onEdit: (id: string) => void;
  /** Omitted (hides the action) for a caller without delete permission. */
  onDelete?: (id: string) => void;
}

const buildColumns = (
  onOpen: (id: string) => void,
  onEdit: (id: string) => void,
  onDelete: ((id: string) => void) | undefined,
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
  {
    /**
     * CITY / STATE, named for what it actually holds.
     *
     * The header used to say "Territory", but `territoryArea` on a live account
     * is built by mapReferralSource as `[city, state].join(', ')` — it is the
     * address the Add/Edit form's City and State inputs write, not the
     * `territoryId` territory the record separately points at. So a marketer who
     * typed a city into the form had nowhere on this screen that said "City":
     * the value was on the row all along, filed under a heading naming a
     * different concept, which is how "the City column is missing" gets reported
     * against a column that is right there.
     *
     * "City / State" rather than two columns because that is the one fact the
     * pair answers (where is this account?), and it matches the wording the
     * locations table already uses for the same pair.
     */
    key: 'territory',
    header: 'City / State',
    cell: (r) => r.territoryArea ?? '—',
  },
  {
    key: 'actions',
    header: '',
    headerClassName: 'w-20',
    className: 'text-right',
    cell: (r) => (
      <EntityRowActions
        onEdit={() => onEdit(r.id)}
        onDelete={onDelete ? () => onDelete(r.id) : undefined}
        editLabel={`Edit ${r.organization}`}
        deleteLabel={`Delete ${r.organization}`}
      />
    ),
  },
];

export function ReferralsTable({ items, onOpen, onEdit, onDelete }: ReferralsTableProps) {
  return (
    <DataTable
      columns={buildColumns(onOpen, onEdit, onDelete)}
      rows={items}
      rowKey={(r) => r.id}
      empty="No referral sources match your filters."
    />
  );
}

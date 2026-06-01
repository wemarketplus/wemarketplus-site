import { useAppDispatch } from '@/app/hooks';
import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { LeadStatus, type Lead } from '@/shared/types';
import { LEAD_STATUS_LABELS } from '../constants/leadsConstants';
import { updateLeadStatus } from '../store/leadsSlice';

const STATUS_PILL: Record<LeadStatus, PillProps['tone']> = {
  [LeadStatus.Inquiry]: 'b',
  [LeadStatus.TourScheduled]: 'p',
  [LeadStatus.Proposal]: 'y',
  [LeadStatus.FollowUp]: 'b',
  [LeadStatus.MoveIn]: 'g',
  [LeadStatus.Lost]: 'r',
};

export function LeadsTable({ leads }: { leads: readonly Lead[] }) {
  const dispatch = useAppDispatch();

  // Columns built inside so the status <select> can dispatch the override —
  // mirrors the demo's inline updateLeadStatus().
  const columns: ReadonlyArray<Column<Lead>> = [
    {
      key: 'prospect',
      header: 'Prospect',
      cell: (l) => (
        <div>
          <p className="font-bold text-[#111]">{l.name}</p>
          <p className="text-[11px] text-[#667]">{l.email}</p>
        </div>
      ),
    },
    { key: 'care', header: 'Care', cell: (l) => l.careType },
    {
      key: 'status',
      header: 'Status',
      cell: (l) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={STATUS_PILL[l.status]}>{LEAD_STATUS_LABELS[l.status]}</Pill>
          <select
            aria-label={`Change status for ${l.name}`}
            value={l.status}
            onChange={(e) =>
              dispatch(
                updateLeadStatus({ id: l.id, status: e.target.value as LeadStatus }),
              )
            }
            className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
          >
            {Object.values(LeadStatus).map((s) => (
              <option key={s} value={s}>
                {LEAD_STATUS_LABELS[s]}
              </option>
            ))}
          </select>
        </span>
      ),
    },
    { key: 'source', header: 'Source', cell: (l) => l.source },
    { key: 'followUp', header: 'Follow-up', cell: (l) => formatDate(l.followUpDate) },
  ];

  return (
    <DataTable
      columns={columns}
      rows={leads}
      rowKey={(l) => l.id}
      empty="No leads match the current filters."
    />
  );
}

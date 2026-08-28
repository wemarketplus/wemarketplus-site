import { Button } from '@/shared/ui/core';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  LEAD_DISQUALIFY_LABELS,
  LEAD_SOURCE_LABELS,
  LEAD_STATUS_LABELS,
  LEAD_STATUS_PILL,
} from '../constants/leadsConstants';
import type { LeadRecord } from '../types/leadsTypes';
import { isActionable, referralOrigin } from '../utils/leadsUtils';

interface LeadsTableProps {
  items: readonly LeadRecord[];
  isBusy: boolean;
  onConvert: (lead: LeadRecord) => void;
  onDisqualify: (lead: LeadRecord) => void;
}

export function LeadsTable({
  items,
  isBusy,
  onConvert,
  onDisqualify,
}: LeadsTableProps) {
  const columns: ReadonlyArray<Column<LeadRecord>> = [
    {
      key: 'patient',
      header: 'Patient',
      // The patient's NAME, and nothing else. The diagnosis used to be rendered
      // as a second line inside this cell, so a clinical detail read as part of
      // the patient's identity and the "Patient" heading described only half of
      // what sat under it. It has its own column below; the field, the payload
      // and the form are untouched.
      cell: (lead) => (
        <p className="font-bold text-foreground">{lead.patientName ?? '—'}</p>
      ),
    },
    {
      key: 'diagnosis',
      // Matches the intake form's own label for the field it shows
      // (AddLeadModal's "Diagnosis / reason"), so the column and the box that
      // fills it are recognisably the same thing.
      header: 'Diagnosis / reason',
      cell: (lead) =>
        lead.diagnosisReason ? (
          /*
           * Free text up to 2000 chars (see leadSchema), so it is capped and
           * ellipsised rather than allowed to decide the table's width — this
           * table sits in a `min-w-max` element, so an uncapped cell widens the
           * whole grid and pushes Status and the row actions off-screen. The cap
           * is on the BLOCK inside the cell, not on the <td>: a `max-width` on a
           * cell in an auto-layout table is advisory and browsers ignore it,
           * while a block child's max-width caps the column's preferred width
           * for real. `title` keeps the full text reachable on hover.
           */
          <span className="block max-w-[240px] truncate" title={lead.diagnosisReason}>
            {lead.diagnosisReason}
          </span>
        ) : (
          '—'
        ),
    },
    {
      key: 'origin',
      header: 'Referred by',
      cell: (lead) => referralOrigin(lead),
    },
    {
      key: 'source',
      header: 'Source',
      cell: (lead) => LEAD_SOURCE_LABELS[lead.sourceType],
    },
    {
      key: 'received',
      header: 'Received',
      cell: (lead) => formatDate(lead.receivedAt),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (lead) => (
        <div className="space-y-1">
          <Pill tone={LEAD_STATUS_PILL[lead.status]}>
            {LEAD_STATUS_LABELS[lead.status]}
          </Pill>
          {lead.disqualifyReason && (
            <p className="text-[10px] text-muted-soft">
              {LEAD_DISQUALIFY_LABELS[lead.disqualifyReason]}
            </p>
          )}
        </div>
      ),
    },
    {
      key: 'actions',
      header: '',
      // Convert/disqualify disappear once the lead reaches a terminal status —
      // the backend rejects those transitions with 409, so the UI must not offer them.
      cell: (lead) =>
        isActionable(lead) ? (
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              onClick={() => onDisqualify(lead)}
              disabled={isBusy}
            >
              Disqualify
            </Button>
            <Button onClick={() => onConvert(lead)} disabled={isBusy}>
              Convert
            </Button>
          </div>
        ) : (
          <span className="block text-right text-[10px] uppercase tracking-label text-muted-soft">
            {lead.convertedPipelineId ? 'In pipeline' : '—'}
          </span>
        ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={items}
      rowKey={(lead) => lead.id}
      empty="No inbound referrals match your filters."
    />
  );
}

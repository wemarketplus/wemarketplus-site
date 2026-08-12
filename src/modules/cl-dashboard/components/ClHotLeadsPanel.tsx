import { Flame } from 'lucide-react';
import { Link } from 'react-router-dom';
import { CL_LEAD_STAGE, type ClLeadRecord } from '@/modules/cl-leads';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { leadDisplayName } from '../utils/clDashboardMetrics';

/** Plain-English stage names — the guide's journey wording, not the enum. */
const STAGE_LABELS: Record<string, string> = {
  [CL_LEAD_STAGE.Inquiry]: 'Inquiry',
  [CL_LEAD_STAGE.Contacted]: 'Follow-up',
  [CL_LEAD_STAGE.TourScheduled]: 'Tour scheduled',
  [CL_LEAD_STAGE.Toured]: 'Toured',
  [CL_LEAD_STAGE.ProposalSent]: 'Proposal sent',
  [CL_LEAD_STAGE.DepositPaid]: 'Decision pending',
};

/** Rows shown before the panel defers to the full pipeline. */
const MAX_ROWS = 8;

/**
 * "Check the Hot Leads list first, since those need attention today."
 *
 * Each row links into the Lead Pipeline rather than opening a drawer here: the
 * guide's instruction for acting on a lead is "Click View on any lead to update
 * their stage", and that lives on the pipeline screen. A second place to edit a
 * lead is a second place for the stage to be set inconsistently.
 */
export function ClHotLeadsPanel({ leads }: { leads: readonly ClLeadRecord[] }) {
  const today = formatDate(new Date(), 'yyyy-MM-dd');

  return (
    <Card>
      <CardContent className="px-0 pb-0 pt-0">
        <header className="flex flex-wrap items-center gap-3 px-6 py-4">
          <span className="rounded-[10px] bg-destructive/[0.10] p-2 text-destructive">
            <Flame className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-foreground">Hot leads</h2>
            <p className="text-[11px] text-muted-soft">
              Work these first — they need attention today.
            </p>
          </div>
          {leads.length > 0 && <Pill tone="r">{leads.length}</Pill>}
        </header>

        {leads.length === 0 ? (
          <p className="px-6 pb-5 text-xs text-muted-soft">
            No hot leads right now. Mark a lead urgent from the Lead Pipeline and
            it will appear here.
          </p>
        ) : (
          <ul className="border-t border-border/[0.09]">
            {leads.slice(0, MAX_ROWS).map((lead) => {
              // A promised call-back whose date has passed. Compared as
              // YYYY-MM-DD strings so "today" never flips on a timezone offset.
              const overdue = !!lead.followUpDate && lead.followUpDate < today;
              return (
                <li
                  key={lead.id}
                  className="border-b border-border/[0.06] last:border-b-0"
                >
                  <Link
                    to="/leads"
                    className="flex flex-wrap items-center gap-3 px-6 py-3 transition-colors hover:bg-foreground/[0.03]"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13px] font-semibold text-foreground">
                        {leadDisplayName(lead)}
                      </p>
                      <p className="truncate text-[11px] text-muted-soft">
                        {STAGE_LABELS[lead.stage] ?? lead.stage}
                        {lead.phone && ` · ${lead.phone}`}
                        {lead.source && ` · via ${lead.source}`}
                      </p>
                    </div>
                    {lead.followUpDate && (
                      <Pill tone={overdue ? 'r' : 'y'}>
                        {overdue ? 'Overdue' : 'Follow up'}{' '}
                        {formatDate(lead.followUpDate, 'MMM d')}
                      </Pill>
                    )}
                  </Link>
                </li>
              );
            })}
          </ul>
        )}

        {leads.length > MAX_ROWS && (
          <div className="border-t border-border/[0.09] px-6 py-3">
            <Link
              to="/leads"
              className="text-[12px] font-bold text-primary hover:underline"
            >
              View all {leads.length} in Lead Pipeline →
            </Link>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

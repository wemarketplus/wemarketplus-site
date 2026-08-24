import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { RotateCcw } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill, StatTile } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { useListReengagementQuery } from '../api/prospectsApi';
import { STAGE_LABELS } from '../constants/prospectsConstants';

/** The queue is a worklist; the tail is not meant to be paged through. */
const QUEUE_LIMIT = 50;

/**
 * The re-engagement queue: open referrals that have gone quiet.
 *
 * Its own destination as well as a section on Daily tasks, because working the
 * back catalogue is a deliberate sitting rather than something squeezed between
 * today's visits — the client lists it as a place you go.
 *
 * Inactivity is computed SERVER-side from notes, completed visits, completed
 * jobs and stage changes. It is deliberately not `updatedAt`, which any field
 * edit would reset — correcting a phone number would otherwise mark a
 * three-month-silent referral as freshly worked.
 */
export function ReengagementPage() {
  const { data, isLoading, isError } = useListReengagementQuery({
    limit: QUEUE_LIMIT,
  });

  const rows = data ?? [];
  const longest = rows.length > 0 ? rows[rows.length - 1].daysInactive : 0;

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>
          Re-engagement queue
        </h1>
        <p className="text-sm text-muted">
          Open referrals with no activity for 30 days — a good place to start
          your win-them-back calls.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <StatTile
          label="Gone quiet"
          value={String(rows.length)}
          tone={rows.length > 0 ? 'y' : 'g'}
          icon={RotateCcw}
        />
        <StatTile
          label="Longest silence"
          value={rows.length > 0 ? `${longest} days` : '—'}
          tone={longest >= 60 ? 'r' : 'y'}
        />
        <StatTile
          label="Threshold"
          value="30 days"
          hint="Set server-side"
          tone="b"
        />
      </div>

      {isError ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            We could not load the queue right now. Please try again in a moment.
          </CardContent>
        </Card>
      ) : isLoading ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading the queue…
          </CardContent>
        </Card>
      ) : rows.length === 0 ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted-soft">
            Nothing has gone quiet. Every open referral has had activity in the
            last 30 days.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="px-0 py-0">
            {/* Longest-quiet first — the list is a call order, not an index. */}
            <ul className="divide-y divide-border">
              {rows.map((row) => (
                <li
                  key={row.prospect.id}
                  className="flex flex-wrap items-center gap-3 px-6 py-3.5"
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-foreground">
                      {row.prospect.patientName}
                    </p>
                    <p className="text-[11px] text-muted-soft">
                      {row.prospect.facilityName ?? 'No facility'} · last
                      activity {formatDate(row.lastActivityAt)}
                    </p>
                  </div>
                  <Pill tone="b">
                    {STAGE_LABELS[row.prospect.stage] ?? row.prospect.stage}
                  </Pill>
                  <span
                    className={
                      row.daysInactive >= 60
                        ? 'text-xs font-semibold tabular-nums text-destructive'
                        : 'text-xs font-semibold tabular-nums text-warning'
                    }
                  >
                    {row.daysInactive} days quiet
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

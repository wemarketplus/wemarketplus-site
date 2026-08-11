import { useMemo, useState } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { Alert, DataTable, Pill, SectionHeader } from '@/shared/ui/data-display';
import type { Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { cn } from '@/shared/utils/cn';
import { useGetReferralScorecardQuery } from '../api/intelligenceApi';
import { RANGES, rangeToWindow } from '../constants/intelligenceConstants';
import { setIntelligenceRange } from '../store/intelligenceSlice';
import type { ReferralScorecardRow } from '../types/intelligenceTypes';

const currency = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  maximumFractionDigits: 0,
});

/**
 * Score bands. Deliberately three, not ten: an office manager plans around
 * "protect / watch / fix", and a ten-colour scale is unreadable at a glance.
 */
const scoreTone = (score: number): 'g' | 'y' | 'r' =>
  score >= 7 ? 'g' : score >= 4 ? 'y' : 'r';

/**
 * The automatic 1-10 referral source scorecard.
 *
 * Shows the computed grade next to the team's HAND-SET score, because the gap
 * between them is the point: an account the team rates 9 and the data rates 3 is
 * exactly the conversation this report exists to start. Neither number is
 * presented as the truth over the other.
 *
 * Every grade is expandable into the signed factors that produced it. A score a
 * manager cannot interrogate is a score they will not act on — and the rubric is
 * deterministic (see referral-scorecard.constants.ts), so there is always a
 * straight answer.
 */
export function ReferralScorecardPage() {
  const dispatch = useAppDispatch();
  const range = useAppSelector((s) => s.intelligence.range);
  const params = useMemo(() => rangeToWindow(range), [range]);
  const { data, isLoading, isFetching, error } =
    useGetReferralScorecardQuery(params);
  const [expanded, setExpanded] = useState<string | null>(null);

  const columns: Column<ReferralScorecardRow>[] = [
    {
      key: 'score',
      header: 'Score',
      className: 'w-20',
      cell: (row) => (
        <Pill tone={scoreTone(row.score)}>{row.score.toFixed(1)}</Pill>
      ),
    },
    {
      key: 'name',
      header: 'Referral source',
      cell: (row) => (
        <button
          type="button"
          onClick={() =>
            setExpanded((current) =>
              current === row.referralSourceId ? null : row.referralSourceId,
            )
          }
          className="text-left font-semibold text-foreground underline-offset-2 hover:underline"
        >
          {row.name}
        </button>
      ),
    },
    {
      key: 'handSetScore',
      header: 'Team score',
      cell: (row) => (
        <span
          className={cn(
            'font-mono text-xs',
            // Flag a meaningful disagreement — that is the finding, not the score.
            row.handSetScore !== null &&
              Math.abs(row.handSetScore - row.score) >= 3
              ? 'font-bold text-warning'
              : 'text-muted',
          )}
        >
          {row.handSetScore === null ? '—' : row.handSetScore.toFixed(1)}
        </span>
      ),
    },
    {
      key: 'admits',
      header: 'Admits',
      cell: (row) => <span className="text-sm">{row.admits}</span>,
    },
    {
      key: 'referrals',
      header: 'Referrals',
      cell: (row) => <span className="text-sm text-muted">{row.referrals}</span>,
    },
    {
      key: 'revenue',
      header: 'Revenue',
      cell: (row) => (
        <span className="text-sm">{currency.format(row.revenue)}</span>
      ),
    },
    {
      key: 'touches',
      header: 'Touches',
      cell: (row) => <span className="text-sm text-muted">{row.touches}</span>,
    },
    {
      key: 'lastInteractionAt',
      header: 'Last touch',
      cell: (row) => (
        <span className="text-xs text-muted">
          {row.lastInteractionAt ? formatDate(row.lastInteractionAt) : 'Never'}
        </span>
      ),
    },
  ];

  const expandedRow = data?.rows.find((r) => r.referralSourceId === expanded);

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">
            Referral source scorecard
          </h1>
          <p className="text-sm text-muted">
            An automatic 1–10 grade per account, from admissions, conversion,
            recency, revenue and logged effort.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => dispatch(setIntelligenceRange(r.value))}
              className={cn(
                'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
                range === r.value
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
              )}
            >
              {r.label}
            </button>
          ))}
        </div>
      </header>

      {error && (
        <Alert tone="r">
          <strong className="font-bold">Scorecard could not be loaded.</strong> No
          grades are shown rather than stale or estimated ones. Retry, or check
          that your plan includes the Intelligence group.
        </Alert>
      )}

      {!error && !isLoading && data?.rows.length === 0 && (
        <Alert tone="b">
          <strong className="font-bold">No referral sources yet.</strong> Add the
          facilities you receive referrals from and they will be graded as
          activity accumulates.
        </Alert>
      )}

      <section className="space-y-3">
        <SectionHeader
          title="Accounts"
          subtitle="Highest score first. Select an account to see exactly which factors produced its grade."
        />
        <DataTable
          columns={columns}
          rows={data?.rows ?? []}
          rowKey={(row) => row.referralSourceId}
          empty={isLoading || isFetching ? 'Loading…' : 'No accounts to grade.'}
        />
      </section>

      {expandedRow && (
        <section className="space-y-3">
          <SectionHeader
            title={`Why ${expandedRow.name} scores ${expandedRow.score.toFixed(1)}`}
            subtitle="Each factor is a signed adjustment to a neutral 5.5 baseline. The rubric is fixed and documented — this is not a model."
          />
          <div className="rounded-[14px] border border-border/[0.09] bg-surface">
            {expandedRow.factors.length === 0 ? (
              <p className="px-5 py-4 text-sm text-muted">
                No factors applied — this account scores the neutral baseline.
              </p>
            ) : (
              <ul className="divide-y divide-border/[0.06]">
                {expandedRow.factors.map((factor) => (
                  <li
                    key={factor.key}
                    className="flex items-center justify-between gap-4 px-5 py-3"
                  >
                    <span className="text-sm text-foreground">{factor.detail}</span>
                    <span
                      className={cn(
                        'shrink-0 font-mono text-sm font-bold',
                        factor.points >= 0 ? 'text-success' : 'text-destructive',
                      )}
                    >
                      {factor.points > 0 ? '+' : ''}
                      {factor.points.toFixed(1)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      )}

      {data && (
        <p className="text-xs text-muted-soft">
          Computed {formatDate(data.computedAt)} over{' '}
          {formatDate(data.window.from)} – {formatDate(data.window.to)}. Scores are
          saved to each account when this report runs.
        </p>
      )}
    </div>
  );
}

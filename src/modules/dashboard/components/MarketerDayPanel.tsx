import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { AlertTriangle, Flame, Footprints, PhoneCall, UserPlus } from 'lucide-react';
import type { ComponentType } from 'react';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import { useGetMyDayQuery } from '../api/dashboardApi';
import type { DashboardMetric, HotAlert, MetricProgress } from '../types/dashboardTypes';

const METRIC_LABELS: Record<DashboardMetric, string> = {
  visits: 'Visits',
  calls: 'Calls',
  referrals: 'Referrals',
};

const METRIC_ICONS: Record<DashboardMetric, ComponentType<{ className?: string }>> = {
  visits: Footprints,
  calls: PhoneCall,
  referrals: UserPlus,
};

/** Progress toward a target, clamped so an over-achieved goal fills the bar. */
function pct(progress: MetricProgress): number {
  if (!progress.target || progress.target <= 0) return 0;
  return Math.min(100, Math.round((progress.achieved / progress.target) * 100));
}

function MetricTile({ progress }: { progress: MetricProgress }) {
  const Icon = METRIC_ICONS[progress.metric];
  const hasTarget = progress.target !== null && progress.target > 0;
  const hit = hasTarget && progress.achieved >= (progress.target ?? 0);

  return (
    <div className="rounded-card border border-border/[0.09] bg-surface px-5 py-5">
      <div className="flex items-start justify-between gap-3">
        <p className="text-[10.5px] font-semibold uppercase tracking-label text-muted-soft">
          {METRIC_LABELS[progress.metric]} this week
        </p>
        <span className="rounded-md bg-primary/[0.08] p-2 text-primary">
          <Icon className="h-4 w-4" />
        </span>
      </div>

      <p className="mt-3 font-display text-3xl leading-none text-foreground">
        {progress.achieved}
        {hasTarget && (
          <span className="text-base text-muted-soft"> / {progress.target}</span>
        )}
      </p>

      {hasTarget ? (
        <div className="mt-3 h-1.5 w-full overflow-hidden rounded-pill bg-foreground/[0.06]">
          <div
            className={cn(
              'h-full rounded-pill transition-all',
              hit ? 'bg-success' : 'bg-primary',
            )}
            style={{ width: `${pct(progress)}%` }}
          />
        </div>
      ) : (
        // No target is a real state, not a broken tile. Say what to do about it
        // rather than showing an empty progress bar that implies zero progress.
        <p className="mt-3 text-[11px] text-muted-soft">
          No weekly target set — add one under Daily goals
        </p>
      )}
    </div>
  );
}

function AlertRow({ alert }: { alert: HotAlert }) {
  const overdue = alert.reason === 'overdue_work';
  return (
    <li className="flex flex-wrap items-center gap-3 px-6 py-3">
      <span
        className={cn(
          'rounded-sm p-1.5',
          overdue
            ? 'bg-destructive/[0.10] text-destructive'
            : 'bg-warning/[0.12] text-warning',
        )}
      >
        {overdue ? (
          <AlertTriangle className="h-3.5 w-3.5" />
        ) : (
          <Flame className="h-3.5 w-3.5" />
        )}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-foreground">
          {alert.patientName}
          {alert.facilityName && (
            <span className="ml-2 text-[11px] font-normal text-muted-soft">
              {alert.facilityName}
            </span>
          )}
        </p>
        <p className="text-[11px] text-muted-soft">{alert.detail}</p>
      </div>
      {alert.aiAdmitScore !== null && (
        <Pill tone={alert.aiAdmitScore >= 7.5 ? 'g' : alert.aiAdmitScore >= 5 ? 'y' : 'r'}>
          {alert.aiAdmitScore.toFixed(1)}
        </Pill>
      )}
      <Pill tone={overdue ? 'r' : 'y'}>
        {overdue ? 'Overdue' : 'Hot'}
      </Pill>
    </li>
  );
}

/**
 * The marketer's morning: how they are pacing this week, and what needs them
 * today.
 *
 * Reads `/dashboard/my-day`, which is scoped to the caller — deliberately not
 * the tenant-wide summary, which carries figures (overdue invoices) a field
 * user has no access to act on.
 */
export function MarketerDayPanel() {
  const { data, isLoading, isError } = useGetMyDayQuery();

  if (isError) return null;

  if (isLoading || !data) {
    return (
      <Card>
        <CardContent className="px-6 py-6 text-xs text-muted-soft">
          Loading your week…
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {data.goals.map((progress) => (
          <MetricTile key={progress.metric} progress={progress} />
        ))}
      </div>

      <Card>
        <CardContent className="px-0 pb-0 pt-0">
          <header className="flex flex-wrap items-center gap-3 px-6 py-4">
            <span
              className={cn(
                'rounded-md p-2',
                data.hotAlerts.length > 0
                  ? 'bg-destructive/[0.10] text-destructive'
                  : 'bg-success/[0.10] text-success',
              )}
            >
              <AlertTriangle className="h-4 w-4" />
            </span>
            <div className="min-w-0 flex-1">
              <h2 className={SECTION_TITLE}>
                Needs you today
              </h2>
              <p className="text-[11px] text-muted-soft">
                Overdue field work and hot referrals on your prospects
              </p>
            </div>
            {data.hotAlerts.length > 0 && (
              <Pill tone="r">{data.hotAlerts.length}</Pill>
            )}
          </header>

          {data.hotAlerts.length === 0 ? (
            <p className="px-6 pb-5 text-xs text-muted-soft">
              Nothing urgent — no overdue work and no hot referrals waiting.
            </p>
          ) : (
            <ul className="divide-y divide-border border-t border-border">
              {data.hotAlerts.map((alert) => (
                <AlertRow key={alert.prospectId} alert={alert} />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

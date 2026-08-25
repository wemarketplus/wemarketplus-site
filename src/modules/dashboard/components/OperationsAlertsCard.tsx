import { Link } from 'react-router-dom';
import { CheckCircle2, TriangleAlert } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeader } from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import type { OperationsAlert } from '../utils/operationsAlerts';

const TONE_ROW: Record<OperationsAlert['tone'], string> = {
  destructive: 'border-destructive/25 bg-destructive/[0.05]',
  warning: 'border-warning/25 bg-warning/[0.05]',
  success: 'border-success/25 bg-success/[0.05]',
};

const TONE_TITLE: Record<OperationsAlert['tone'], string> = {
  destructive: 'text-destructive',
  warning: 'text-warning',
  success: 'text-success',
};

/**
 * Operations Alerts — the Executive Director's "jump straight into action" panel.
 *
 * Presentational only: `buildOperationsAlerts` decides what is worth saying, so
 * the thresholds live in a pure, testable function rather than in JSX.
 *
 * Each row carries exactly ONE button. The panel's job is to end in a decision,
 * and a row offering three routes is a row the reader has to think about instead
 * of act on.
 */
export function OperationsAlertsCard({
  alerts,
}: {
  alerts: readonly OperationsAlert[];
}) {
  return (
    <Card>
      <CardContent className="space-y-4 pt-6">
        <SectionHeader
          title="Operations alerts"
          subtitle="What needs a decision today"
        />

        {alerts.length === 0 ? (
          <p className="flex items-center gap-2 rounded-lg border border-success/25 bg-success/[0.05] px-3.5 py-3 text-[13px] text-muted">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />
            Nothing needs you right now — no units on notice, no open work orders,
            no hot leads.
          </p>
        ) : (
          <ul className="space-y-2.5">
            {alerts.map((alert) => (
              <li
                key={alert.id}
                className={cn(
                  'flex flex-col gap-2.5 rounded-lg border px-3.5 py-3 sm:flex-row sm:items-center',
                  TONE_ROW[alert.tone],
                )}
              >
                <div className="min-w-0 flex-1">
                  <p
                    className={cn(
                      'flex items-center gap-1.5 text-[13px] font-bold',
                      TONE_TITLE[alert.tone],
                    )}
                  >
                    <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                    {alert.title}
                  </p>
                  <p className="mt-0.5 text-[12px] leading-snug text-muted">
                    {alert.detail}
                  </p>
                </div>
                {/* A Link, not a Button-with-onClick: it navigates, so it must be
                    middle-clickable and copyable like any other link. */}
                <Link
                  to={alert.to}
                  className="shrink-0 self-start rounded-pill border border-border/[0.14] bg-surface-raised px-3 py-1.5 text-[11.5px] font-semibold text-foreground transition-colors hover:border-border/30 sm:self-auto"
                >
                  {alert.actionLabel}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

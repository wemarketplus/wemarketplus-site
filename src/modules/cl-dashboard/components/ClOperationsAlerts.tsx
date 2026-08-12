import { AlertTriangle, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';

export interface ClOpsAlert {
  id: string;
  label: string;
  detail: string;
  /** Warnings tint; a healthy, informational row stays neutral. */
  urgent: boolean;
  actionLabel: string;
  to: string;
}

/**
 * "Use the Operations Alerts on your dashboard to jump straight into action —
 * buttons like 'Schedule Make-Ready' or 'View Leads' take you right where you
 * need to go."
 *
 * Every row is a LINK to an existing screen, never an inline mutation. The guide
 * describes this panel as a set of shortcuts, and a director who turns a unit
 * from here would be doing it without the context (the other tasks on that unit,
 * who is free) that the Make-Ready Board shows.
 */
export function ClOperationsAlerts({
  alerts,
}: {
  alerts: readonly ClOpsAlert[];
}) {
  return (
    <Card>
      <CardContent className="px-0 pb-0 pt-0">
        <header className="flex flex-wrap items-center gap-3 px-6 py-4">
          <span className="rounded-[10px] bg-warning/[0.12] p-2 text-warning">
            <AlertTriangle className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-foreground">
              Operations alerts
            </h2>
            <p className="text-[11px] text-muted-soft">
              What needs a decision today, and where to go to make it.
            </p>
          </div>
        </header>

        {alerts.length === 0 ? (
          <p className="px-6 pb-5 text-xs text-muted-soft">
            Nothing needs attention — occupancy, make-readies and work orders are
            all clear.
          </p>
        ) : (
          <ul className="border-t border-border/[0.09]">
            {alerts.map((alert) => (
              <li
                key={alert.id}
                className="border-b border-border/[0.06] last:border-b-0"
              >
                <Link
                  to={alert.to}
                  className="flex flex-wrap items-center gap-3 px-6 py-3.5 transition-colors hover:bg-foreground/[0.03]"
                >
                  <span
                    className={cn(
                      'mt-1 h-2 w-2 shrink-0 rounded-full',
                      alert.urgent ? 'bg-destructive' : 'bg-success',
                    )}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[13px] font-semibold text-foreground">
                      {alert.label}
                    </p>
                    <p className="truncate text-[11px] text-muted-soft">
                      {alert.detail}
                    </p>
                  </div>
                  <span className="inline-flex shrink-0 items-center gap-1 rounded-pill border border-border/[0.12] px-3 py-1 text-[11px] font-bold text-foreground">
                    {alert.actionLabel}
                    <ArrowRight className="h-3 w-3" />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

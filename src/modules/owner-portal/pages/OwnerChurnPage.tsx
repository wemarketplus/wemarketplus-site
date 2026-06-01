import { AlertTriangle } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_CHURN } from '../constants/ownerFixtures';

const RECOVERY_LABEL = {
  none: 'Not contacted',
  email_sent: 'Email sent',
  call_scheduled: 'Call scheduled',
  recovered: 'Recovered',
} as const;

const RECOVERY_TONE = {
  none: 'border-destructive/30 bg-destructive/10 text-destructive',
  email_sent: 'border-warning/30 bg-warning/10 text-warning',
  call_scheduled: 'border-azure/30 bg-azure/10 text-azure',
  recovered: 'border-success/30 bg-success/10 text-success',
} as const;

export function OwnerChurnPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Churn & risk"
        description="Accounts in danger of leaving and recovery progress."
      />

      <Card>
        <CardContent className="px-0 pt-0 pb-0">
          <ul className="divide-y divide-white/[0.06]">
            {OWNER_CHURN.map((row) => (
              <li key={row.id} className="flex items-start gap-4 px-6 py-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-warning/15 text-warning ring-1 ring-warning/30">
                  <AlertTriangle className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-foreground">
                    {row.organization}
                  </p>
                  <p className="mt-0.5 text-xs text-muted">{row.reason}</p>
                  <p className="mt-1 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                    Idle {row.daysIdle} days
                  </p>
                </div>
                <span
                  className={`shrink-0 rounded-pill border px-2.5 py-1 text-[10px] uppercase tracking-[0.08em] ${RECOVERY_TONE[row.recoveryAttempt]}`}
                >
                  {RECOVERY_LABEL[row.recoveryAttempt]}
                </span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

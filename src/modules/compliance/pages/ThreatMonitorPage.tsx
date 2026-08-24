import { Card, CardContent } from '@/shared/ui/core';
import { Pill, StatTile, type StatTone } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import { useThreatMonitorQuery } from '../api/complianceApi';
import { PortalShell } from '../components/PortalShell';
import { RISK_PILL } from '../constants/complianceConstants';

/**
 * Security posture, computed server-side from `audit_logs`.
 *
 * This page previously rendered THREAT_METRICS and SECURITY_EVENTS — hard-coded
 * fixtures reading "Failed Logins (24h): 3", "Threat Level: Low" and three invented
 * events with realistic-looking email addresses — under the heading "Real-time
 * security metrics". A fabricated all-clear is worse than no monitor at all,
 * because an administrator reads it and stops looking.
 *
 * Every figure now comes from real audit rows. Where an input is not collected, the
 * tile shows "—" and states why rather than showing a reassuring zero.
 */
export function ThreatMonitorPage() {
  const { data, isLoading, isError } = useThreatMonitorQuery();

  return (
    <PortalShell
      title="Security Threat Monitor"
      description="Computed from this workspace's audit log. Figures marked — are not collected yet."
    >
      {isError ? (
        <EmptyState
          title="Could not load security metrics"
          description="The audit log did not respond. Nothing is implied about your security posture — try again."
        />
      ) : isLoading ? (
        <p className="text-sm text-muted-soft">Reading the audit log…</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
            {(data?.metrics ?? []).map((m) => (
              <div key={m.label}>
                <StatTile
                  label={m.label}
                  value={m.value ?? '—'}
                  tone={m.tone as StatTone}
                />
                {m.unavailableReason && (
                  <p className="mt-1 text-[11px] text-muted-soft">
                    {m.unavailableReason}
                  </p>
                )}
              </div>
            ))}
          </div>

          <Card dense className="mt-4">
            <CardContent className="px-0 pt-0 pb-0">
              <header className="px-6 py-4">
                <p className="text-[10px] uppercase tracking-label text-muted-soft">
                  Recent security events
                </p>
              </header>
              {(data?.events ?? []).length === 0 ? (
                <p className="px-6 pb-5 text-sm text-muted">
                  No sign-ins, failed logins, password resets or permission changes
                  recorded yet.
                </p>
              ) : (
                <ul className="divide-y divide-white/[0.06]">
                  {(data?.events ?? []).map((e) => (
                    <li key={e.id} className="flex items-start gap-3 px-6 py-3">
                      <Pill tone={RISK_PILL[e.risk]}>{e.risk}</Pill>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-foreground">
                          {e.type}
                        </p>
                        <p className="text-xs text-muted">{e.detail}</p>
                      </div>
                      <span className="shrink-0 text-[10px] uppercase tracking-label text-muted-soft">
                        {formatDateTime(e.occurredAt)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </PortalShell>
  );
}

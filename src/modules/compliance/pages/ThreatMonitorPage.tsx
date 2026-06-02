import { Card, CardContent } from '@/shared/ui/core';
import { Pill, StatTile, type StatTone } from '@/shared/ui/data-display';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import { PortalShell } from '../components/PortalShell';
import { SECURITY_EVENTS, THREAT_METRICS } from '../constants/portalContent';
import { RISK_PILL } from '../constants/complianceConstants';

export function ThreatMonitorPage() {
  return (
    <PortalShell
      title="Security Threat Monitor"
      description="Real-time security metrics. Alerts fire automatically for critical events."
    >
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {THREAT_METRICS.map((m) => (
          <StatTile key={m.label} label={m.label} value={m.value} tone={m.tone as StatTone} />
        ))}
      </div>

      <Card dense className="mt-4">
        <CardContent className="px-0 pt-0 pb-0">
          <header className="px-6 py-4">
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
              Recent Security Events
            </p>
          </header>
          <ul className="divide-y divide-white/[0.06]">
            {SECURITY_EVENTS.map((e) => (
              <li key={e.id} className="flex items-start gap-3 px-6 py-3">
                <Pill tone={RISK_PILL[e.risk]}>{e.risk}</Pill>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-foreground">{e.type}</p>
                  <p className="text-xs text-muted">{e.detail}</p>
                </div>
                <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                  {formatDateTime(e.occurredAt)}
                </span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </PortalShell>
  );
}

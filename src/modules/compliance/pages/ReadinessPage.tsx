import { Card, CardContent } from '@/shared/ui/core';
import { Pill, type PillProps } from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import { PortalShell } from '../components/PortalShell';
import { useReadiness } from '../hooks/useReadiness';
import type { ControlStatus } from '../types/complianceTypes';

const STATUS_PILL: Record<ControlStatus, PillProps['tone']> = {
  compliant: 'g',
  partial: 'y',
  'at-risk': 'r',
};
const STATUS_LABEL: Record<ControlStatus, string> = {
  compliant: 'Compliant',
  partial: 'Partial',
  'at-risk': 'At risk',
};

export function ReadinessPage() {
  const { readiness } = useReadiness();
  const auditReady = readiness.status === 'audit-ready';

  return (
    <PortalShell
      title="HIPAA Readiness Score"
      description="Current compliance posture. Run monthly for audit evidence."
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card dense>
          <CardContent className="flex flex-col items-center justify-center gap-1 px-6 py-8 text-center">
            <p className="font-display text-6xl font-black leading-none text-azure">
              {readiness.score}
            </p>
            <p className="mt-1 text-[13px] uppercase tracking-[0.1em] text-muted">
              Rating {readiness.rating}
            </p>
            <span
              className={cn(
                'mt-3 rounded-pill border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.08em]',
                auditReady
                  ? 'border-success/30 bg-success/10 text-success'
                  : 'border-warning/30 bg-warning/10 text-warning',
              )}
            >
              {auditReady ? '✅ Audit Ready' : '⚠️ Needs Remediation'}
            </span>
          </CardContent>
        </Card>

        <Card dense className="lg:col-span-2">
          <CardContent className="px-0 pt-0 pb-0">
            <table className="w-full text-[13px]">
              <thead className="bg-white/[0.02] text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                <tr>
                  <th className="px-4 py-3 text-left">Control</th>
                  <th className="px-4 py-3 text-left">Score</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.05]">
                {readiness.controls.map((c) => (
                  <tr key={c.control}>
                    <td className="px-4 py-3 font-semibold text-foreground">{c.control}</td>
                    <td className="px-4 py-3 text-muted">
                      {c.achieved}/{c.weight}
                    </td>
                    <td className="px-4 py-3">
                      <Pill tone={STATUS_PILL[c.status]}>{STATUS_LABEL[c.status]}</Pill>
                    </td>
                    <td className="px-4 py-3 text-muted">{c.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>
    </PortalShell>
  );
}

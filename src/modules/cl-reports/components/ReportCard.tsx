import { Download } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { formatRelative } from '@/shared/utils/dateFormatter';
import type { ReportCardProps, ClReportResult } from '../types/clReportsTypes';
import { useReportCard } from '../hooks/useReportCard';

interface Props extends ReportCardProps {
  // Live computed metrics for this report (CommunityLink only). Undefined for
  // fixture-only products, where the card stays a static template.
  live?: ClReportResult;
}

export function ReportCard({ report, live }: Props) {
  const { onRun, isRunning } = useReportCard(report);
  return (
    <Card>
      <CardContent className="space-y-3 px-5 py-5">
        <div>
          <h2 className="text-sm font-semibold text-foreground">{report.title}</h2>
          <p className="mt-1 text-sm text-muted">{report.description}</p>
        </div>

        {live && !live.unavailable && live.metrics.length > 0 && (
          <dl className="space-y-1.5 border-t border-white/[0.06] pt-3">
            {live.metrics.map((m) => (
              <div key={m.metric} className="flex items-center justify-between gap-2">
                <dt className="text-[12px] text-muted">{m.metric}</dt>
                <dd
                  className={
                    m.tone === 'r'
                      ? 'text-[12px] font-bold text-destructive'
                      : m.tone === 'g'
                        ? 'text-[12px] font-bold text-success'
                        : 'text-[12px] font-bold text-foreground'
                  }
                >
                  {m.value}
                </dd>
              </div>
            ))}
          </dl>
        )}

        {live?.unavailable && (
          <p className="border-t border-white/[0.06] pt-3 text-[12px] text-muted-soft">
            {live.note ?? 'No data source available yet.'}
          </p>
        )}

        <div className="flex items-center justify-between">
          <p className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
            {report.lastRunAt
              ? `Last run ${formatRelative(report.lastRunAt)}`
              : 'Live data'}
          </p>
          <Button
            size="sm"
            variant="secondary"
            onClick={onRun}
            disabled={isRunning || live?.unavailable}
          >
            <Download className="h-4 w-4" /> {isRunning ? 'Exporting…' : 'Export CSV'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

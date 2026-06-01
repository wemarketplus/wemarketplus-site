import { Download } from 'lucide-react';
import { toast } from 'sonner';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { formatRelative } from '@/shared/utils/dateFormatter';
import type { ReportDefinition } from '../types/clReportsTypes';

export function ReportCard({ report }: { report: ReportDefinition }) {
  return (
    <Card>
      <CardContent className="space-y-3 px-5 py-5">
        <div>
          <h2 className="text-sm font-semibold text-foreground">{report.title}</h2>
          <p className="mt-1 text-sm text-muted">{report.description}</p>
        </div>
        <div className="flex items-center justify-between">
          <p className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
            {report.lastRunAt
              ? `Last run ${formatRelative(report.lastRunAt)}`
              : 'Never run'}
          </p>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => toast.message(`${report.title} — export pending backend`)}
          >
            <Download className="h-4 w-4" /> Run
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

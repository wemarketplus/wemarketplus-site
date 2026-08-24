import { Card, CardContent } from '@/shared/ui/core';
import type { IntelligenceKpi } from '../types/intelligenceTypes';

export function IntelligenceKpiTile({ kpi }: { kpi: IntelligenceKpi }) {
  return (
    <Card>
      <CardContent className="space-y-2 px-5 py-5">
        <p className="text-[10px] uppercase tracking-label text-muted-soft">
          {kpi.label}
        </p>
        <p className="font-display text-3xl leading-none text-foreground">{kpi.value}</p>
        {kpi.delta && (
          <p className="text-[11px] font-semibold uppercase tracking-label text-success">
            {kpi.delta}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

import { DataTable, StatTile, type Column } from '@/shared/ui/data-display';
import type { OwnerMetrics } from '../types/ownerPortalApiTypes';

// Live platform metrics — GET /owner/metrics returns the cross-tenant sales
// pipeline broken down by stage. This is the only revenue-adjacent figure the
// backend exposes today (MRR / ARR remain fixtures).
interface OwnerMetricsPanelProps {
  metrics: OwnerMetrics;
}

type StageRow = { stage: string; count: number };

const columns: ReadonlyArray<Column<StageRow>> = [
  {
    key: 'stage',
    header: 'Stage',
    cell: (r) => <span className="font-bold text-foreground capitalize">{r.stage}</span>,
  },
  { key: 'count', header: 'Records', cell: (r) => r.count },
];

export function OwnerMetricsPanel({ metrics }: OwnerMetricsPanelProps) {
  const stages = metrics.pipelineByStage;
  const topStage = [...stages].sort((a, b) => b.count - a.count)[0];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile
          label="Total pipeline"
          value={String(metrics.totalPipeline)}
          hint="Records across all stages"
          tone="b"
        />
        <StatTile label="Active stages" value={String(stages.length)} tone="g" />
        <StatTile
          label="Largest stage"
          value={topStage ? String(topStage.count) : '0'}
          hint={topStage ? topStage.stage : undefined}
          tone="gd"
        />
      </div>

      <DataTable
        columns={columns}
        rows={stages}
        rowKey={(r) => r.stage}
        empty="No pipeline records yet."
      />
    </div>
  );
}

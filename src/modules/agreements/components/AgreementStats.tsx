import { StatTile } from '@/shared/ui/data-display';
import type { AgreementStats as AgreementStatsData } from '../types/agreementsTypes';

interface AgreementStatsProps {
  stats?: AgreementStatsData;
}

// Summary tiles fed by GET /agreements/stats. Renders nothing until the stats
// query resolves.
export function AgreementStats({ stats }: AgreementStatsProps) {
  if (!stats) return null;

  const money = `$${stats.totalValue.toLocaleString()}`;

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <StatTile label="Total" value={String(stats.total)} tone="b" />
      <StatTile label="Active" value={String(stats.active)} tone="g" />
      <StatTile label="Pending signature" value={String(stats.pendingSignature)} tone="y" />
      <StatTile label="Total value" value={money} tone="gd" />
    </div>
  );
}

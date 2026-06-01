import { Card, CardContent } from '@/shared/ui/core';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerKpiTile } from '../components/OwnerKpiTile';
import { useOwnerKpis } from '../hooks/useOwnerKpis';
import { OWNER_INSIGHTS } from '../constants/ownerFixtures';

export function OwnerDashboardPage() {
  const { kpis } = useOwnerKpis();
  const highlightInsight = OWNER_INSIGHTS[0];

  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Command dashboard"
        description="Top-line metrics across the whole business."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {kpis.map((k) => (
          <OwnerKpiTile key={k.id} kpi={k} />
        ))}
      </div>

      {highlightInsight && (
        <Card>
          <CardContent className="space-y-2 px-6 py-5">
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
              AI highlight
            </p>
            <h2 className="text-base font-semibold text-foreground">
              {highlightInsight.title}
            </h2>
            <p className="text-sm text-muted">{highlightInsight.summary}</p>
            <p className="text-sm text-foreground">
              <span className="font-semibold text-primary">Recommend: </span>
              {highlightInsight.recommendation}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

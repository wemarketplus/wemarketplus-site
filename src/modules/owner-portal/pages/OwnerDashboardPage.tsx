import { Card, CardContent } from '@/shared/ui/core';
import { useFeatureFlag } from '@/modules/feature-flags';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';
import { OwnerKpiTile } from '../components/OwnerKpiTile';
import { useOwnerKpis } from '../hooks/useOwnerKpis';
import { OWNER_INSIGHTS } from '../constants/ownerFixtures';

export function OwnerDashboardPage() {
  const { kpis } = useOwnerKpis();
  const highlightInsight = OWNER_INSIGHTS[0];
  // Example flag-gated UI: this beta strip only renders when a SuperAdmin has
  // turned on `ai_insights_beta` (globally or for this tenant) via the feature
  // flags screen — demonstrating the useFeatureFlag hook end to end.
  const { isEnabled: aiInsightsBeta } = useFeatureFlag('ai_insights_beta');

  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Command dashboard"
        description="Top-line metrics across the whole business."
        actions={<OwnerPreviewNotice />}
      />

      {aiInsightsBeta && (
        <div className="rounded-lg border border-primary/20 bg-primary/[0.06] px-4 py-3 text-sm text-foreground">
          <span className="font-semibold text-primary">AI insights (beta): </span>
          You have early access to experimental business insights.
        </div>
      )}

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

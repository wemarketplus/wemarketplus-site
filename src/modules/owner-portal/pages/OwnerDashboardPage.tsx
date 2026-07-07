import { Card, CardContent } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { Sparkles } from 'lucide-react';
import { useFeatureFlag } from '@/modules/feature-flags';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';
import { OwnerKpiTile } from '../components/OwnerKpiTile';
import { useOwnerKpis } from '../hooks/useOwnerKpis';

export function OwnerDashboardPage() {
  const { kpis } = useOwnerKpis();
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

      <Card>
        <CardContent className="px-6 py-5">
          <EmptyState
            icon={Sparkles}
            title="AI insights coming soon"
            description="The analytics endpoint that powers AI business highlights is not yet available."
          />
        </CardContent>
      </Card>
    </div>
  );
}

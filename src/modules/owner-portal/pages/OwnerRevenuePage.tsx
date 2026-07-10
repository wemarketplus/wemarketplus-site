import { LineChart } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerMetricsPanel } from '../components/OwnerMetricsPanel';
import { OwnerQueryState } from '../components/OwnerQueryState';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';
import { useGetOwnerMetricsQuery } from '../api/ownerPortalApi';

export function OwnerRevenuePage() {
  const { data: metrics, isLoading, error } = useGetOwnerMetricsQuery();

  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Revenue intelligence"
        description="Live pipeline metrics, plus a preview of the MRR and ARR reporting to come."
      />

      <OwnerQueryState isLoading={isLoading} error={error}>
        {metrics && <OwnerMetricsPanel metrics={metrics} />}
      </OwnerQueryState>

      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <h2 className="font-display text-xl text-foreground">MRR and ARR trend</h2>
          <OwnerPreviewNotice />
        </div>
        <Card>
          <CardContent className="px-0 pt-0 pb-0">
            <EmptyState
              icon={LineChart}
              title="MRR and ARR trend"
              description="Revenue analytics require a billing-metrics endpoint (not yet available)."
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

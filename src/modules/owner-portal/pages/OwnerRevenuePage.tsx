import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerMetricsPanel } from '../components/OwnerMetricsPanel';
import { OwnerQueryState } from '../components/OwnerQueryState';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';
import { OwnerRevenueChart } from '../components/OwnerRevenueChart';
import { OwnerRevenueTable } from '../components/OwnerRevenueTable';
import { useGetOwnerMetricsQuery } from '../api/ownerPortalApi';
import { OWNER_REVENUE_MONTHS } from '../constants/ownerFixtures';

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
        <OwnerRevenueChart months={OWNER_REVENUE_MONTHS} />
        <OwnerRevenueTable months={OWNER_REVENUE_MONTHS} />
      </div>
    </div>
  );
}

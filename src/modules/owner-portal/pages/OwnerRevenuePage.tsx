import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerRevenueChart } from '../components/OwnerRevenueChart';
import { OwnerRevenueTable } from '../components/OwnerRevenueTable';
import { OWNER_REVENUE_MONTHS } from '../constants/ownerFixtures';

export function OwnerRevenuePage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Revenue intelligence"
        description="MRR, ARR, expansion, and churn over the last 12 months."
      />

      <OwnerRevenueChart months={OWNER_REVENUE_MONTHS} />
      <OwnerRevenueTable months={OWNER_REVENUE_MONTHS} />
    </div>
  );
}

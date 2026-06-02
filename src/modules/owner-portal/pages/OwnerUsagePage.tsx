import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerUsageTable } from '../components/OwnerUsageTable';
import { OWNER_USAGE } from '../constants/ownerFixtures';

export function OwnerUsagePage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Product usage"
        description="Seat consumption and API activity per customer."
      />
      <OwnerUsageTable rows={OWNER_USAGE} />
    </div>
  );
}

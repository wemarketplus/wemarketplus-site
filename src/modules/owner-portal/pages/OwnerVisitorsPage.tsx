import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerVisitorsTable } from '../components/OwnerVisitorsTable';
import { OWNER_VISITORS } from '../constants/ownerFixtures';

export function OwnerVisitorsPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Website visitors"
        description="The marketing-site funnel in real time."
      />
      <OwnerVisitorsTable visitors={OWNER_VISITORS} />
    </div>
  );
}

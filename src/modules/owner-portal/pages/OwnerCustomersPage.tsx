import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerCustomersTable } from '../components/OwnerCustomersTable';
import { OWNER_CUSTOMERS } from '../constants/ownerFixtures';

export function OwnerCustomersPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Customer database"
        description="Every active and churned account with health scores."
      />

      <OwnerCustomersTable customers={OWNER_CUSTOMERS} />
    </div>
  );
}

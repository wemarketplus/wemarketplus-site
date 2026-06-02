import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerAuditTable } from '../components/OwnerAuditTable';
import { OWNER_AUDIT } from '../constants/ownerFixtures';

export function OwnerSecurityPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Security & audit"
        description="Every privileged action across the platform."
      />
      <OwnerAuditTable entries={OWNER_AUDIT} />
    </div>
  );
}

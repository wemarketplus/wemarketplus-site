import { PortalShell } from '../components/PortalShell';
import { BaaRecordsTable } from '../components/BaaRecordsTable';
import { BAA_RECORDS_FIXTURE } from '../constants/portalContent';

export function BaaRecordsPage() {
  return (
    <PortalShell
      title="Business Associate Agreements"
      description="HIPAA requires a signed BAA before any PHI access. Records stored permanently."
    >
      <BaaRecordsTable records={BAA_RECORDS_FIXTURE} />
    </PortalShell>
  );
}

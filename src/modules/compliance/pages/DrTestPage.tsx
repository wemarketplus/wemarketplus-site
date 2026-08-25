import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { PortalShell } from '../components/PortalShell';
import { useDrTest } from '../hooks/useDrTest';

export function DrTestPage() {
  const { onRun } = useDrTest();
  return (
    <PortalShell
      title="Disaster Recovery Test"
      description="Validates data integrity, tenant isolation, and recovery systems. Results logged to audit trail."
    >
      <Card dense>
        <CardContent className="space-y-4 px-6 py-6">
          <div>
            <h2 className={SECTION_TITLE}>Run DR Validation</h2>
            <p className="mt-1 text-sm text-muted">
              Tests: DB read validation, referential integrity, tenant isolation, backup
              verification.
            </p>
          </div>
          <Button onClick={onRun}>
            ▶ Run DR Test Now
          </Button>
        </CardContent>
      </Card>
    </PortalShell>
  );
}

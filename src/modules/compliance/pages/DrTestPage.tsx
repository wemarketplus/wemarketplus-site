import { toast } from 'sonner';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { PortalShell } from '../components/PortalShell';

export function DrTestPage() {
  return (
    <PortalShell
      title="Disaster Recovery Test"
      description="Validates data integrity, tenant isolation, and recovery systems. Results logged to audit trail."
    >
      <Card dense>
        <CardContent className="space-y-4 px-6 py-6">
          <div>
            <h2 className="text-base font-semibold text-foreground">Run DR Validation</h2>
            <p className="mt-1 text-sm text-muted">
              Tests: DB read validation, referential integrity, tenant isolation, backup
              verification.
            </p>
          </div>
          <Button onClick={() => toast.message('DR test — backend endpoint pending')}>
            ▶ Run DR Test Now
          </Button>
        </CardContent>
      </Card>
    </PortalShell>
  );
}

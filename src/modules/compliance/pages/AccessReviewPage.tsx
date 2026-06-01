import { toast } from 'sonner';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { PortalShell } from '../components/PortalShell';

export function AccessReviewPage() {
  return (
    <PortalShell
      title="Access Review"
      description="HIPAA requirement: review user access every 90 days. Run and save results as audit evidence."
    >
      <Card dense>
        <CardContent className="space-y-4 px-6 py-6">
          <p className="text-sm text-muted">
            Last review: <span className="text-foreground">never</span>
          </p>
          <Button
            onClick={() => toast.message('Access review — backend endpoint pending')}
          >
            ▶ Run Access Review
          </Button>
        </CardContent>
      </Card>
    </PortalShell>
  );
}

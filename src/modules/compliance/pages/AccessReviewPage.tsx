import { Button, Card, CardContent } from '@/shared/ui/core';
import { PortalShell } from '../components/PortalShell';
import { useAccessReview } from '../hooks/useAccessReview';

export function AccessReviewPage() {
  const { onRun } = useAccessReview();
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
          <Button onClick={onRun}>
            ▶ Run Access Review
          </Button>
        </CardContent>
      </Card>
    </PortalShell>
  );
}

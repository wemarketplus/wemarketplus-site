import { BarChart3 } from 'lucide-react';
import { Card } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';

export function OwnerVisitorsPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Website visitors"
        description="The marketing-site funnel in real time."
        actions={<OwnerPreviewNotice />}
      />
      <Card>
        <EmptyState
          icon={BarChart3}
          title="Visitor analytics are not available yet"
          description="The marketing-site funnel endpoint has not shipped. Once the analytics API is live, real visitor sessions will appear here."
        />
      </Card>
    </div>
  );
}

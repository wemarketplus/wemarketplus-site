import { Activity } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';

export function OwnerUsagePage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Product usage"
        description="Seat consumption and API activity per customer."
        actions={<OwnerPreviewNotice />}
      />

      <Card>
        <CardContent className="px-0 pt-0 pb-0">
          <EmptyState
            icon={Activity}
            title="Usage analytics are not available yet"
            description="The owner usage endpoint has not shipped. Once it is live, seat consumption and API activity per customer will appear here."
          />
        </CardContent>
      </Card>
    </div>
  );
}

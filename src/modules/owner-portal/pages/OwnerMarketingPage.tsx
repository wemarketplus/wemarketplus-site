import { BarChart3 } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';

export function OwnerMarketingPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Marketing performance"
        description="Spend, leads, and conversion by channel."
        actions={<OwnerPreviewNotice />}
      />

      <Card>
        <CardContent className="px-5 py-5">
          <EmptyState
            icon={BarChart3}
            title="Marketing analytics not available yet"
            description="The marketing performance endpoint has not shipped. Spend, leads, and conversion by channel will appear here once it is connected."
          />
        </CardContent>
      </Card>
    </div>
  );
}

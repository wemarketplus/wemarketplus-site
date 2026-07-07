import { Bot } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';

export function OwnerInsightsPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="AI business insights"
        description="Patterns and recommendations from your operating data."
        actions={<OwnerPreviewNotice />}
      />

      <Card>
        <CardContent className="px-6 py-5">
          <EmptyState
            icon={Bot}
            title="Insights are not available yet"
            description="The AI business insights analytics endpoint has not shipped yet. Recommendations will appear here once it is connected."
          />
        </CardContent>
      </Card>
    </div>
  );
}

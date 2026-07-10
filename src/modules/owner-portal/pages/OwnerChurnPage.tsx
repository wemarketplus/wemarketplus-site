import { AlertTriangle } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';

export function OwnerChurnPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Churn & risk"
        description="Accounts in danger of leaving and recovery progress."
        actions={<OwnerPreviewNotice />}
      />

      <Card>
        <CardContent className="px-0 pt-0 pb-0">
          <EmptyState
            icon={AlertTriangle}
            title="Churn analytics are not available yet"
            description="The owner churn and recovery endpoint has not shipped. Once it is live, at-risk accounts and their recovery progress will appear here."
          />
        </CardContent>
      </Card>
    </div>
  );
}

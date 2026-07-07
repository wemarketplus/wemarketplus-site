import { MessagesSquare } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';

export function OwnerCommunicationPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Communication log"
        description="Every touch with customers, in one place."
        actions={<OwnerPreviewNotice />}
      />

      <Card>
        <CardContent className="px-5 py-5">
          <EmptyState
            icon={MessagesSquare}
            title="Communication analytics not available yet"
            description="The communication log endpoint has not shipped. Emails, calls, and in-app touches with customers will appear here once it is connected."
          />
        </CardContent>
      </Card>
    </div>
  );
}

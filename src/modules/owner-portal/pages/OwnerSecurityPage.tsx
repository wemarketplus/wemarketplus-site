import { ShieldAlert } from 'lucide-react';
import { EmptyState } from '@/shared/ui/feedback';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPreviewNotice } from '../components/OwnerPreviewNotice';

export function OwnerSecurityPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Security & audit"
        description="Every privileged action across the platform."
        actions={<OwnerPreviewNotice />}
      />
      <div className="rounded-[12px] border border-white/[0.08] bg-surface">
        <EmptyState
          icon={ShieldAlert}
          title="Audit analytics not available yet"
          description="The platform-wide security audit endpoint has not shipped yet. Once it is available, privileged actions across every tenant will appear here."
        />
      </div>
    </div>
  );
}

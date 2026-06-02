import { Card, CardContent } from '@/shared/ui/core';
import { formatRelative } from '@/shared/utils/dateFormatter';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_COMMUNICATIONS } from '../constants/ownerFixtures';
import { CHANNEL_ICON } from '../constants/ownerScreenConstants';

export function OwnerCommunicationPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Communication log"
        description="Every touch with customers, in one place."
      />

      <Card>
        <CardContent className="px-0 pt-0 pb-0">
          <ul className="divide-y divide-white/[0.06]">
            {OWNER_COMMUNICATIONS.map((c) => {
              const Icon = CHANNEL_ICON[c.channel];
              return (
                <li key={c.id} className="flex items-start gap-4 px-6 py-4">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-white/[0.04] text-muted-soft">
                    <Icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-foreground">{c.with}</p>
                    <p className="mt-0.5 text-xs text-muted">{c.topic}</p>
                  </div>
                  <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                    {formatRelative(c.occurredAt)}
                  </span>
                </li>
              );
            })}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

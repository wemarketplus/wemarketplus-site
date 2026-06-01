import { Bot } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_INSIGHTS } from '../constants/ownerFixtures';
import { cn } from '@/shared/utils/cn';

const SEVERITY_TONE = {
  info: 'border-azure/30 bg-azure/10 text-azure',
  opportunity: 'border-primary/30 bg-primary/10 text-primary',
  risk: 'border-destructive/30 bg-destructive/10 text-destructive',
} as const;

export function OwnerInsightsPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="AI business insights"
        description="Patterns and recommendations from your operating data."
      />

      <div className="space-y-3">
        {OWNER_INSIGHTS.map((i) => (
          <Card key={i.id}>
            <CardContent className="flex items-start gap-4 px-6 py-5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
                <Bot className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-semibold text-foreground">{i.title}</h2>
                  <span
                    className={cn(
                      'rounded-pill border px-2 py-0.5 text-[10px] uppercase tracking-[0.08em]',
                      SEVERITY_TONE[i.severity],
                    )}
                  >
                    {i.severity}
                  </span>
                </div>
                <p className="mt-1 text-sm text-muted">{i.summary}</p>
                <p className="mt-2 text-sm text-foreground">
                  <span className="font-semibold text-primary">Recommend: </span>
                  {i.recommendation}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

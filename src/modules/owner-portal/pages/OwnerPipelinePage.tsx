import { Card, CardContent } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_PIPELINE } from '../constants/ownerFixtures';
import { formatMoney } from '../utils/ownerFormat';

const STAGES: Array<{
  value: typeof OWNER_PIPELINE[number]['stage'];
  label: string;
  tone: string;
}> = [
  { value: 'demo', label: 'Demo', tone: 'text-azure' },
  { value: 'pilot', label: 'Pilot', tone: 'text-primary' },
  { value: 'contract', label: 'Contract', tone: 'text-warning' },
  { value: 'won', label: 'Won', tone: 'text-success' },
  { value: 'lost', label: 'Lost', tone: 'text-destructive' },
];

export function OwnerPipelinePage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Sales pipeline"
        description="Every deal in motion grouped by stage."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        {STAGES.map((stage) => {
          const deals = OWNER_PIPELINE.filter((d) => d.stage === stage.value);
          const total = deals.reduce((n, d) => n + d.estimatedMrr, 0);
          return (
            <Card key={stage.value} className="flex flex-col">
              <CardContent className="flex h-full flex-col gap-3 px-4 py-4">
                <div className="flex items-center justify-between">
                  <p className={`text-[11px] font-semibold uppercase tracking-[0.1em] ${stage.tone}`}>
                    {stage.label}
                  </p>
                  <p className="text-[10px] text-muted-soft">{deals.length}</p>
                </div>
                <p className="text-xs text-muted">{formatMoney(total)} estimated</p>
                <ul className="space-y-2">
                  {deals.map((d) => (
                    <li
                      key={d.id}
                      className="rounded-md border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-xs"
                    >
                      <p className="font-semibold text-foreground">{d.prospect}</p>
                      <p className="mt-0.5 text-muted-soft">
                        {formatMoney(d.estimatedMrr)} · {formatDate(d.closeBy)}
                      </p>
                      <p className="mt-0.5 text-muted">{d.owner}</p>
                    </li>
                  ))}
                  {deals.length === 0 && (
                    <li className="rounded-md border border-dashed border-white/[0.06] px-3 py-2 text-xs text-muted-soft">
                      No deals
                    </li>
                  )}
                </ul>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

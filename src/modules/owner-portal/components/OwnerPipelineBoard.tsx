import { Card, CardContent } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import { formatMoney } from '../utils/ownerFormat';
import { dealsForStage, sumEstimatedMrr } from '../utils/ownerPipeline';
import { STAGES } from '../constants/ownerScreenConstants';
import type { OwnerPipelineBoardProps } from '../types/ownerPortalTypes';

export function OwnerPipelineBoard({ deals }: OwnerPipelineBoardProps) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
      {STAGES.map((stage) => {
        const stageDeals = dealsForStage(deals, stage.value);
        const total = sumEstimatedMrr(stageDeals);
        return (
          <Card key={stage.value} className="flex flex-col">
            <CardContent className="flex h-full flex-col gap-3 px-4 py-4">
              <div className="flex items-center justify-between">
                <p className={`text-[11px] font-semibold uppercase tracking-[0.1em] ${stage.tone}`}>
                  {stage.label}
                </p>
                <p className="text-[10px] text-muted-soft">{stageDeals.length}</p>
              </div>
              <p className="text-xs text-muted">{formatMoney(total)} estimated</p>
              <ul className="space-y-2">
                {stageDeals.map((d) => (
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
                {stageDeals.length === 0 && (
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
  );
}

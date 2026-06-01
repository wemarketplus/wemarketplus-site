import type { Prospect } from '@/shared/types';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  URGENCY_LABELS,
  URGENCY_TONE,
} from '@/modules/prospects/constants/prospectsConstants';

export function PipelineCard({ prospect }: { prospect: Prospect }) {
  return (
    <article className="space-y-1.5 rounded-md border border-white/[0.06] bg-white/[0.02] px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <p className="truncate text-sm font-semibold text-foreground">
          {prospect.name}
        </p>
        <span
          className={`shrink-0 rounded-pill border px-2 py-0.5 text-[9px] uppercase tracking-[0.08em] ${URGENCY_TONE[prospect.urgency]}`}
        >
          {URGENCY_LABELS[prospect.urgency]}
        </span>
      </div>
      <p className="text-[11px] text-muted">{prospect.referralSource}</p>
      <p className="text-[11px] text-foreground">{prospect.nextStep}</p>
      <p className="text-[10px] uppercase tracking-[0.08em] text-muted-soft">
        {formatDate(prospect.followUpDate)} · {prospect.assignedMarketer}
      </p>
    </article>
  );
}

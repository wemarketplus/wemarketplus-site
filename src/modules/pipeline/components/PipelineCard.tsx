import { GripVertical } from 'lucide-react';
import {
  URGENCY_LABELS,
  URGENCY_TONE,
} from '@/modules/prospects/constants/prospectsConstants';
import type { ProspectRecord } from '@/modules/prospects/types/prospectsTypes';
import type { Urgency } from '@/shared/types';
import { formatDate } from '@/shared/utils/dateFormatter';
import { cn } from '@/shared/utils/cn';
import { cardTitle } from '../utils/pipelineUtils';

interface PipelineCardProps {
  card: ProspectRecord;
  isDragging: boolean;
  onDragStart: () => void;
  onDragEnd: () => void;
}

export function PipelineCard({
  card,
  isDragging,
  onDragStart,
  onDragEnd,
}: PipelineCardProps) {
  return (
    <article
      draggable
      onDragStart={(event) => {
        // The card id travels in the drag payload so a column drop handler can
        // identify it without reaching into global state.
        event.dataTransfer.setData('text/plain', card.id);
        event.dataTransfer.effectAllowed = 'move';
        onDragStart();
      }}
      onDragEnd={onDragEnd}
      className={cn(
        'group cursor-grab space-y-1.5 rounded-md border border-white/[0.06] bg-white/[0.02] px-3 py-2.5 transition',
        'hover:border-white/[0.12] active:cursor-grabbing',
        isDragging && 'opacity-40',
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="truncate text-sm font-semibold text-foreground">
          {cardTitle(card)}
        </p>
        <span
          className={`shrink-0 rounded-pill border px-2 py-0.5 text-[9px] uppercase tracking-[0.08em] ${
            URGENCY_TONE[card.urgency as Urgency]
          }`}
        >
          {URGENCY_LABELS[card.urgency as Urgency]}
        </span>
      </div>
      {card.facilityName && (
        <p className="truncate text-[11px] text-muted">{card.facilityName}</p>
      )}
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] uppercase tracking-[0.08em] text-muted-soft">
          {card.stageEnteredAt
            ? `In stage since ${formatDate(card.stageEnteredAt)}`
            : 'Stage not yet stamped'}
        </p>
        <GripVertical className="h-3 w-3 shrink-0 text-muted-soft opacity-0 transition group-hover:opacity-100" />
      </div>
    </article>
  );
}

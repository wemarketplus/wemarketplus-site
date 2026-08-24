import { useState } from 'react';
import type { ProspectRecord } from '@/modules/prospects/types/prospectsTypes';
import { Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import type { ProspectStage } from '../types/pipelineTypes';
import { stageTone } from '../utils/pipelineUtils';
import { PipelineCard } from './PipelineCard';

interface PipelineColumnProps {
  stage: ProspectStage;
  label: string;
  total: number;
  cards: readonly ProspectRecord[];
  draggingProspectId: string | null;
  onDragStart: (id: string) => void;
  onDragEnd: () => void;
  onDropCard: (prospectId: string, toStage: ProspectStage) => void;
}

export function PipelineColumn({
  stage,
  label,
  total,
  cards,
  draggingProspectId,
  onDragStart,
  onDragEnd,
  onDropCard,
}: PipelineColumnProps) {
  const [isOver, setIsOver] = useState(false);

  return (
    <Card
      className={cn('flex flex-col transition', isOver && 'ring-1 ring-primary/40')}
      onDragOver={(event) => {
        // Must preventDefault for the drop event to fire at all.
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
        setIsOver(true);
      }}
      onDragLeave={() => setIsOver(false)}
      onDrop={(event) => {
        event.preventDefault();
        setIsOver(false);
        const prospectId = event.dataTransfer.getData('text/plain');
        // Dropping a card back on its own column is a no-op, not a wasted request.
        if (prospectId && !cards.some((card) => card.id === prospectId)) {
          onDropCard(prospectId, stage);
        }
      }}
    >
      <CardContent className="flex h-full flex-col gap-3 px-4 py-4">
        <header className="flex items-center justify-between">
          <span
            className={`rounded-pill border px-2.5 py-0.5 text-[10px] uppercase tracking-label ${stageTone(
              stage,
            )}`}
          >
            {label}
          </span>
          <span className="text-[10px] text-muted-soft">{total}</span>
        </header>
        <div className="flex-1 space-y-2">
          {cards.length === 0 ? (
            <p className="rounded-md border border-dashed border-border px-3 py-2 text-xs text-muted-soft">
              Drop a card here
            </p>
          ) : (
            cards.map((card) => (
              <PipelineCard
                key={card.id}
                card={card}
                isDragging={draggingProspectId === card.id}
                onDragStart={() => onDragStart(card.id)}
                onDragEnd={onDragEnd}
              />
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}

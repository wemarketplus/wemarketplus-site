import type { Prospect, ProspectStatus } from '@/shared/types';
import { Card, CardContent } from '@/shared/ui/core';
import { PipelineCard } from './PipelineCard';

interface PipelineColumnProps {
  status: ProspectStatus;
  label: string;
  tone: string;
  items: readonly Prospect[];
}

export function PipelineColumn({ label, tone, items }: PipelineColumnProps) {
  return (
    <Card className="flex flex-col">
      <CardContent className="flex h-full flex-col gap-3 px-4 py-4">
        <header className="flex items-center justify-between">
          <span
            className={`rounded-pill border px-2.5 py-0.5 text-[10px] uppercase tracking-[0.08em] ${tone}`}
          >
            {label}
          </span>
          <span className="text-[10px] text-muted-soft">{items.length}</span>
        </header>
        <div className="flex-1 space-y-2">
          {items.length === 0 ? (
            <p className="rounded-md border border-dashed border-white/[0.06] px-3 py-2 text-xs text-muted-soft">
              No prospects
            </p>
          ) : (
            items.map((p) => <PipelineCard key={p.id} prospect={p} />)
          )}
        </div>
      </CardContent>
    </Card>
  );
}

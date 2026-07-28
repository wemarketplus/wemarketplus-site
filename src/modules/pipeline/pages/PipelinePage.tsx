import { PIPELINE_TYPE_OPTIONS } from '@/modules/prospects/constants/prospectsConstants';
import type { ProspectPipelineType } from '@/modules/prospects/types/prospectsTypes';
import { Card, CardContent, Select } from '@/shared/ui/core';
import { PipelineColumn } from '../components/PipelineColumn';
import { usePipelineBoard } from '../hooks/usePipelineBoard';
import { cardTitle, stageLabel } from '../utils/pipelineUtils';

export function PipelinePage() {
  const {
    pipelineType,
    changePipelineType,
    columns,
    unstaged,
    total,
    isLoading,
    isError,
    isMoving,
    draggingProspectId,
    beginDrag,
    endDrag,
    moveToStage,
  } = usePipelineBoard();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Pipeline</h1>
          <p className="text-sm text-muted">
            {total} open across {columns.length} stages · drag a card to change stage
            {isMoving && (
              <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                Saving
              </span>
            )}
          </p>
        </div>
        <label className="flex items-center gap-2 text-xs text-muted">
          Pipeline
          <Select
            value={pipelineType}
            onChange={(event) =>
              changePipelineType(event.target.value as ProspectPipelineType)
            }
          >
            {PIPELINE_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </label>
      </header>

      {isError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          Could not load the pipeline board.
        </p>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-soft">Loading board…</p>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
          {columns.map((column) => (
            <PipelineColumn
              key={column.stage}
              stage={column.stage}
              label={column.label}
              total={column.total}
              cards={column.cards}
              draggingProspectId={draggingProspectId}
              onDragStart={beginDrag}
              onDragEnd={endDrag}
              onDropCard={moveToStage}
            />
          ))}
        </div>
      )}

      {/* Pre-pipeline rows sit on a legacy stage and have no column. Surfaced so a
          tenant's older records are never invisible on this screen. */}
      {unstaged.length > 0 && (
        <Card>
          <CardContent className="space-y-2 px-5 py-4">
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
              Not on this pipeline ({unstaged.length})
            </p>
            <p className="text-xs text-muted">
              These records use a pre-pipeline stage. Open one to set its stage.
            </p>
            <ul className="divide-y divide-white/[0.06]">
              {unstaged.map((card) => (
                <li
                  key={card.id}
                  className="flex items-center justify-between gap-3 py-2"
                >
                  <span className="truncate text-sm text-foreground">
                    {cardTitle(card)}
                  </span>
                  <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                    {stageLabel(card.stage)}
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

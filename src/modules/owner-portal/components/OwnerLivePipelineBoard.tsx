import { Pencil, Trash2 } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { OWNER_PIPELINE_STAGES } from '../constants/ownerPipelineConstants';
import type { PipelineRecord } from '../types/ownerPortalApiTypes';

// Live sales pipeline board — GET /owner/pipeline. Records are grouped into the
// suggested stage columns; any record whose (free-form) stage is not one of the
// known stages falls into a trailing "Other" column so nothing is hidden.
interface OwnerLivePipelineBoardProps {
  records: readonly PipelineRecord[];
  onEdit: (record: PipelineRecord) => void;
  onDelete: (record: PipelineRecord) => void;
  deletingId: string | null;
}

const OTHER = 'Other';

export function OwnerLivePipelineBoard({
  records,
  onEdit,
  onDelete,
  deletingId,
}: OwnerLivePipelineBoardProps) {
  const known = new Set<string>(OWNER_PIPELINE_STAGES);
  const hasOther = records.some((r) => !known.has(r.stage));
  const columns = hasOther
    ? [...OWNER_PIPELINE_STAGES, OTHER]
    : [...OWNER_PIPELINE_STAGES];

  const forStage = (stage: string) =>
    stage === OTHER
      ? records.filter((r) => !known.has(r.stage))
      : records.filter((r) => r.stage === stage);

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      {columns.map((stage) => {
        const stageRecords = forStage(stage);
        return (
          <Card key={stage} className="flex flex-col">
            <CardContent className="flex h-full flex-col gap-3 px-4 py-4">
              <div className="flex items-center justify-between">
                <p className="text-[11px] font-semibold uppercase tracking-[0.1em] text-primary">
                  {stage}
                </p>
                <p className="text-[10px] text-muted-soft">{stageRecords.length}</p>
              </div>
              <ul className="space-y-2">
                {stageRecords.map((record) => (
                  <li
                    key={record.id}
                    className="rounded-md border border-border/[0.06] bg-foreground/[0.02] px-3 py-2 text-xs"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-foreground">
                          {record.name}
                        </p>
                        {record.company && (
                          <p className="mt-0.5 truncate text-muted-soft">
                            {record.company}
                          </p>
                        )}
                        <p className="mt-0.5 text-muted">
                          {record.conversionPct}% · {record.source ?? 'no source'}
                        </p>
                      </div>
                      <div className="flex shrink-0 gap-1">
                        <button
                          type="button"
                          aria-label="Edit"
                          onClick={() => onEdit(record)}
                          className="flex h-6 w-6 items-center justify-center rounded text-muted hover:bg-foreground/[0.06] hover:text-foreground"
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          aria-label="Delete"
                          disabled={deletingId === record.id}
                          onClick={() => onDelete(record)}
                          className="flex h-6 w-6 items-center justify-center rounded text-muted hover:bg-destructive/15 hover:text-destructive disabled:opacity-40"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
                {stageRecords.length === 0 && (
                  <li className="rounded-md border border-dashed border-border/[0.06] px-3 py-2 text-xs text-muted-soft">
                    No records
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

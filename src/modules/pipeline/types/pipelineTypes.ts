import type {
  PipelineStatus,
  ProspectLostReason,
  ProspectPipelineType,
  ProspectRecord,
  ProspectStage,
} from '@/modules/prospects/types/prospectsTypes';
import type { ID } from '@/shared/types';

export type { ProspectPipelineType, ProspectStage };

// GET /pipeline/board query.
export interface PipelineBoardQuery {
  pipelineType?: ProspectPipelineType;
}

// Mirrors wemarketplus-backend/src/pipeline/dto/pipeline-board-response.dto.ts.
export interface PipelineColumn {
  stage: ProspectStage;
  label: string;
  total: number;
  cards: ProspectRecord[];
}

export interface PipelineBoard {
  pipelineType: ProspectPipelineType;
  columns: PipelineColumn[];
  /** Rows on a legacy stage — surfaced, never silently dropped. */
  unstaged: ProspectRecord[];
}

// POST /pipeline/move body.
export interface MovePipelineStageRequest {
  prospectId: ID;
  toStage: ProspectStage;
  lostReason?: ProspectLostReason;
}

/** Job the transition spawned, when the stage has a blueprint. */
export interface SpawnedJobSummary {
  id: ID;
  jobType: string;
  objective: string | null;
  dueDate: string | null;
  status: string;
}

export interface MovePipelineStageResult {
  prospect: ProspectRecord & { status: PipelineStatus };
  fromStage: ProspectStage;
  toStage: ProspectStage;
  spawnedJob: SpawnedJobSummary | null;
}

export interface PipelineUiState {
  pipelineType: ProspectPipelineType;
  /** Card currently being dragged, so columns can show a drop affordance. */
  draggingProspectId: ID | null;
}

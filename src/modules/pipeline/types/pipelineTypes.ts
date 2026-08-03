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
  /**
   * REQUIRED by the backend when `toStage` is `lost` (unless the row already
   * carries one) — ProspectsService.assertLostReason 400s without it. The board
   * collects it through LostReasonModal before the move is sent.
   */
  lostReason?: ProspectLostReason;
  /** Required when `lostReason` is `other`. */
  lostReasonDetail?: string;
}

/** A drop onto the `lost` column, held while the reason is collected. */
export interface PendingLostMove {
  prospectId: ID;
  cardTitle: string;
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

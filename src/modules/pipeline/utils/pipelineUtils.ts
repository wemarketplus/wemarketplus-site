import { STAGE_LABELS } from '@/modules/prospects/constants/prospectsConstants';
import type { ProspectRecord } from '@/modules/prospects/types/prospectsTypes';
import { DEFAULT_STAGE_TONE, STAGE_TONE } from '../constants/pipelineConstants';
import type { ProspectStage } from '../types/pipelineTypes';

/** Presentation tone for a stage column, with a safe fallback. */
export function stageTone(stage: ProspectStage): string {
  return STAGE_TONE[stage] ?? DEFAULT_STAGE_TONE;
}

/** Label for a stage, falling back to the raw value rather than rendering blank. */
export function stageLabel(stage: ProspectStage): string {
  return STAGE_LABELS[stage] ?? stage;
}

/** Card title: the opportunity name when set, else the patient. */
export function cardTitle(card: ProspectRecord): string {
  return card.pipelineName ?? card.patientName;
}

import { ProspectStage } from '@/modules/prospects/types/prospectsTypes';

export const PIPELINE_TAGS = {
  Board: 'Pipeline.Board',
} as const;

/**
 * Column tint per stage. Keyed by the real backend stage enum; the board's column
 * ORDER and LABELS come from the server (GET /pipeline/board) so they cannot drift.
 * This map only supplies presentation.
 */
export const STAGE_TONE: Record<ProspectStage, string> = {
  // referral-to-admit — cool to warm as the referral progresses
  [ProspectStage.NewReferral]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.Eligibility]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.FaceToFace]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStage.ConsentOrder]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStage.Admitted]: 'border-success/30 bg-success/10 text-success',
  // outreach
  [ProspectStage.Identified]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.FirstVisit]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.InService]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStage.Active]: 'border-success/30 bg-success/10 text-success',
  [ProspectStage.Champion]: 'border-success/30 bg-success/10 text-success',
  // terminal / legacy
  [ProspectStage.Lost]: 'border-white/[0.08] bg-white/[0.03] text-muted',
  [ProspectStage.Inquiry]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.Contacted]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.Pending]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStage.Evaluation]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStage.Inactive]: 'border-white/[0.08] bg-white/[0.03] text-muted',
};

/** Fallback tone for a stage the tone map somehow does not cover. */
export const DEFAULT_STAGE_TONE = 'border-white/[0.08] bg-white/[0.03] text-muted';

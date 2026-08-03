import {
  ProspectLostReason,
  ProspectStage,
} from '@/modules/prospects/types/prospectsTypes';

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
  [ProspectStage.Lost]: 'border-border bg-surface-raised text-muted',
  [ProspectStage.Inquiry]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.Contacted]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStage.Pending]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStage.Evaluation]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStage.Inactive]: 'border-border bg-surface-raised text-muted',
};

/** Fallback tone for a stage the tone map somehow does not cover. */
export const DEFAULT_STAGE_TONE = 'border-border bg-surface-raised text-muted';

/**
 * Why an opportunity was lost. The backend requires one on entry to `lost` on
 * EITHER pipeline (referral-to-admit and outreach), so this list is what the board
 * offers before it will send the move. Values mirror
 * wemarketplus-backend/src/prospects/prospects.constants.ts ProspectLostReason.
 */
export const LOST_REASON_LABELS: Record<ProspectLostReason, string> = {
  [ProspectLostReason.NotEligible]: 'Not eligible',
  [ProspectLostReason.ChoseCompetitor]: 'Chose a competitor hospice',
  [ProspectLostReason.Declined]: 'Family declined',
  [ProspectLostReason.Deceased]: 'Passed before enrollment',
  [ProspectLostReason.Other]: 'Other (please describe)',
};

export const LOST_REASON_OPTIONS = (
  Object.values(ProspectLostReason) as ProspectLostReason[]
).map((value) => ({ value, label: LOST_REASON_LABELS[value] }));

/** The one reason that also requires free text before the move is accepted. */
export const LOST_REASON_REQUIRING_DETAIL = ProspectLostReason.Other;

export const LOST_REASON_DETAIL_MAX_LENGTH = 500;

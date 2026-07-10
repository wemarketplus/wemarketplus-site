import { ProspectStatus, Urgency } from '@/shared/types';
import type { PillProps } from '@/shared/ui/data-display';
import {
  URGENCY_LABELS,
  URGENCY_TONE,
} from '@/shared/constants/urgencyConstants';
import { ProspectStage, ProspectUrgency } from '../types/prospectsTypes';

export { URGENCY_LABELS, URGENCY_TONE };

export const PROSPECTS_TAGS = {
  List: 'Prospects.List',
  Detail: 'Prospects.Detail',
} as const;

export const PROSPECT_STATUS_LABELS: Record<ProspectStatus, string> = {
  [ProspectStatus.Inquiry]: 'Inquiry',
  [ProspectStatus.PendingAdmission]: 'Pending admission',
  [ProspectStatus.Admitted]: 'Admitted',
  [ProspectStatus.Lost]: 'Lost',
};

export const STATUS_TONE: Record<ProspectStatus, string> = {
  [ProspectStatus.Inquiry]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStatus.PendingAdmission]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStatus.Admitted]: 'border-success/30 bg-success/10 text-success',
  [ProspectStatus.Lost]: 'border-white/[0.08] bg-white/[0.03] text-muted',
};

// Pastel pill tones (matching crm-*.html .pill-*) per status/urgency.
export const STATUS_PILL: Record<ProspectStatus, PillProps['tone']> = {
  [ProspectStatus.Inquiry]: 'b',
  [ProspectStatus.PendingAdmission]: 'y',
  [ProspectStatus.Admitted]: 'g',
  [ProspectStatus.Lost]: 'r',
};

export const URGENCY_PILL: Record<Urgency, PillProps['tone']> = {
  [Urgency.Hot]: 'r',
  [Urgency.Warm]: 'y',
  [Urgency.Cold]: 'b',
};

export const STATUS_CHIPS: ReadonlyArray<{ value: ProspectStatus | 'all'; label: string }> = [
  { value: 'all', label: 'All statuses' },
  { value: ProspectStatus.Inquiry, label: PROSPECT_STATUS_LABELS.inquiry },
  { value: ProspectStatus.PendingAdmission, label: PROSPECT_STATUS_LABELS.pending_admission },
  { value: ProspectStatus.Admitted, label: PROSPECT_STATUS_LABELS.admitted },
  { value: ProspectStatus.Lost, label: PROSPECT_STATUS_LABELS.lost },
];

export const URGENCY_CHIPS: ReadonlyArray<{ value: Urgency | 'all'; label: string }> = [
  { value: 'all', label: 'Any urgency' },
  { value: Urgency.Hot, label: URGENCY_LABELS.hot },
  { value: Urgency.Warm, label: URGENCY_LABELS.warm },
  { value: Urgency.Cold, label: URGENCY_LABELS.cold },
];

// Select options for the Add-prospect form (backend stage/urgency enums).
export const PROSPECT_STAGE_OPTIONS: ReadonlyArray<{ value: ProspectStage; label: string }> = [
  { value: ProspectStage.Inquiry, label: 'Inquiry' },
  { value: ProspectStage.Contacted, label: 'Contacted' },
  { value: ProspectStage.Pending, label: 'Pending admission' },
  { value: ProspectStage.Evaluation, label: 'Evaluation' },
  { value: ProspectStage.Admitted, label: 'Admitted' },
  { value: ProspectStage.Lost, label: 'Lost' },
];

export const PROSPECT_URGENCY_OPTIONS: ReadonlyArray<{ value: ProspectUrgency; label: string }> = [
  { value: ProspectUrgency.Hot, label: 'Hot' },
  { value: ProspectUrgency.Warm, label: 'Warm' },
  { value: ProspectUrgency.Cold, label: 'Cold' },
];

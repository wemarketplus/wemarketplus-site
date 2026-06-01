import {
  ProspectStatus,
  Urgency,
  type Prospect,
} from '@/shared/types';

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

export const URGENCY_LABELS: Record<Urgency, string> = {
  [Urgency.Hot]: 'Hot',
  [Urgency.Warm]: 'Warm',
  [Urgency.Cold]: 'Cold',
};

export const URGENCY_TONE: Record<Urgency, string> = {
  [Urgency.Hot]: 'border-destructive/30 bg-destructive/10 text-destructive',
  [Urgency.Warm]: 'border-warning/30 bg-warning/10 text-warning',
  [Urgency.Cold]: 'border-azure/30 bg-azure/10 text-azure',
};

export const STATUS_TONE: Record<ProspectStatus, string> = {
  [ProspectStatus.Inquiry]: 'border-azure/30 bg-azure/10 text-azure',
  [ProspectStatus.PendingAdmission]: 'border-warning/30 bg-warning/10 text-warning',
  [ProspectStatus.Admitted]: 'border-success/30 bg-success/10 text-success',
  [ProspectStatus.Lost]: 'border-white/[0.08] bg-white/[0.03] text-muted',
};

export type ProspectField = keyof Prospect;

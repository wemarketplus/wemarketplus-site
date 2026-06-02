import { Urgency } from '@/shared/types';

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

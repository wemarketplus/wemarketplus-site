import type { ClinicalFeature } from '../types/clinicalTypes';

export const STATUS_LABEL: Record<ClinicalFeature['status'], string> = {
  available: 'Available',
  beta: 'Beta',
  coming_soon: 'Coming soon',
};

export const STATUS_TONE: Record<ClinicalFeature['status'], string> = {
  available: 'border-success/30 bg-success/10 text-success',
  beta: 'border-warning/30 bg-warning/10 text-warning',
  coming_soon: 'border-white/[0.08] bg-white/[0.03] text-muted-soft',
};

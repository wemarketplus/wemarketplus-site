import type { IntegrationTile } from '../types/integrationsTypes';

export const STATUS_TONE: Record<IntegrationTile['status'], string> = {
  connected: 'border-success/30 bg-success/10 text-success',
  available: 'border-white/[0.08] bg-white/[0.03] text-muted-soft',
  beta: 'border-warning/30 bg-warning/10 text-warning',
};

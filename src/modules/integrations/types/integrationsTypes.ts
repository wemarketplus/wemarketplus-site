import type { ComponentType } from 'react';

export interface IntegrationTile {
  id: string;
  name: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
  status: 'connected' | 'available' | 'beta';
  category: 'data' | 'communications' | 'workflow' | 'analytics';
}

export interface IntegrationsUiState {
  category: IntegrationTile['category'] | 'all';
}

// --- Component prop types ---

export interface IntegrationTileCardProps {
  tile: IntegrationTile;
}

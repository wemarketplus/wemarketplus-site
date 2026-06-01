import type { ComponentType } from 'react';

export interface ClinicalFeature {
  id: string;
  title: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
  status: 'available' | 'beta' | 'coming_soon';
}

export interface ClinicalUiState {
  _placeholder: true;
}

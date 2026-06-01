import type {
  Apartment,
  MakeReadyTicket,
  ServiceTicket,
} from '@/shared/types';

export type { Apartment, MakeReadyTicket, ServiceTicket };

export interface ClOperationsUiState {
  view: 'inventory' | 'make-ready' | 'maintenance' | 'housekeeping';
}

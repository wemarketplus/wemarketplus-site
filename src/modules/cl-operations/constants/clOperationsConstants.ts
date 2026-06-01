import { ApartmentStatus, TicketStatus } from '@/shared/types';
import type { ClOperationsUiState } from '../types/clOperationsTypes';

export const OPERATIONS_VIEWS: ReadonlyArray<{
  value: ClOperationsUiState['view'];
  label: string;
}> = [
  { value: 'inventory', label: 'Apartments' },
  { value: 'make-ready', label: 'Make-ready' },
  { value: 'maintenance', label: 'Maintenance' },
  { value: 'housekeeping', label: 'Housekeeping' },
];

export const APARTMENT_STATUS_LABEL: Record<ApartmentStatus, string> = {
  [ApartmentStatus.Available]: 'Available',
  [ApartmentStatus.Occupied]: 'Occupied',
  [ApartmentStatus.Reserved]: 'Reserved',
  [ApartmentStatus.OnNotice]: 'On notice',
  [ApartmentStatus.MakeReady]: 'Make-ready',
  [ApartmentStatus.Maintenance]: 'Maintenance',
  [ApartmentStatus.Offline]: 'Offline',
};

export const TICKET_STATUS_LABEL: Record<TicketStatus, string> = {
  [TicketStatus.Open]: 'Open',
  [TicketStatus.InProgress]: 'In progress',
  [TicketStatus.Completed]: 'Done',
};

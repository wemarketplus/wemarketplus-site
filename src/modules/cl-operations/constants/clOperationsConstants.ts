import { ApartmentStatus, TicketPriority, TicketStatus } from '@/shared/types';
import type { PillProps } from '@/shared/ui/data-display';
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

export const APARTMENT_STATUS_PILL: Record<ApartmentStatus, PillProps['tone']> = {
  [ApartmentStatus.Available]: 'g',
  [ApartmentStatus.Occupied]: 'b',
  [ApartmentStatus.Reserved]: 'p',
  [ApartmentStatus.OnNotice]: 'y',
  [ApartmentStatus.MakeReady]: 'y',
  [ApartmentStatus.Maintenance]: 'r',
  [ApartmentStatus.Offline]: 'b',
};

export const TICKET_PRIORITY_PILL: Record<TicketPriority, PillProps['tone']> = {
  [TicketPriority.Urgent]: 'r',
  [TicketPriority.High]: 'y',
  [TicketPriority.Medium]: 'b',
  [TicketPriority.Low]: 'b',
};

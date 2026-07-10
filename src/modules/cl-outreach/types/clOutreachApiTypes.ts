import type { ID, ISODateString } from '@/shared/types';
import type { ClTaskStatus, TicketPriority } from '../constants/clOutreachApiConstants';

// Backend record shapes for CommunityLink outreach — wemarketplus-backend
// cl/outreach-visits, cl/tasks.
export interface ClOutreachVisitRecord {
  id: ID;
  tenantId: ID;
  referralSourceId: ID | null;
  visitDate: string;
  locationName: string | null;
  contactName: string | null;
  visitType: string | null;
  miles: number | null;
  gpsLat: number | null;
  gpsLng: number | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClOutreachVisitRequest {
  referralSourceId?: string;
  visitDate: string;
  locationName?: string;
  contactName?: string;
  visitType?: string;
  miles?: number;
  gpsLat?: number;
  gpsLng?: number;
  notes?: string;
}

export interface ClTaskRecord {
  id: ID;
  tenantId: ID;
  title: string;
  description: string | null;
  leadId: ID | null;
  assignedTo: ID | null;
  dueDate: string | null;
  priority: TicketPriority;
  status: ClTaskStatus;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClTaskRequest {
  title: string;
  description?: string;
  leadId?: string;
  assignedTo?: string;
  dueDate?: string;
  priority?: TicketPriority;
  status?: ClTaskStatus;
}

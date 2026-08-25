import type { ID, ISODateString } from '@/shared/types';
import type { ClTaskStatus, TicketPriority } from '../constants/clOutreachApiConstants';

// Backend record shapes for CommunityLink outreach — wemarketplus-backend
// cl/outreach-visits, cl/tasks.
export interface ClOutreachVisitRecord {
  id: ID;
  tenantId: ID;
  /**
   * The field worker who made the visit — WHO OWNS THIS ROW.
   *
   * Non-nullable, because the column is: `cl_outreach_visits.userId` is `uuid`
   * NOT NULL and `ClOutreachVisitController.create` fills it from the JWT
   * (`{ ...dto, userId: actor.id }`), so a visit cannot exist without one. It is
   * deliberately absent from `CreateClOutreachVisitRequest` below for the same
   * reason: it is derived from the caller, never sent by the client, and a
   * writable owner field would let one rep log a visit as another.
   *
   * This field was MISSING from this type while the backend was already
   * returning it, which made the shared CommunityLink calendar paint every
   * facility visit in the grey unassigned colour — the visit's owner was thrown
   * away at the type boundary rather than at the API. See visitToEvent in
   * modules/cl-calendar.
   */
  userId: ID;
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

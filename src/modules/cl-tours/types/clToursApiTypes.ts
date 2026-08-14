import type { ID, ISODateString } from '@/shared/types';
import type { ClTourStatus } from '../constants/clToursApiConstants';

// Backend record shapes for CommunityLink tours (wemarketplus-backend cl/tours).
export interface ClTourRecord {
  id: ID;
  tenantId: ID;
  leadId: ID | null;
  guideUserId: ID | null;
  scheduledAt: ISODateString;
  durationMin: number | null;
  status: ClTourStatus;
  /**
   * When the family confirmed, or null while the booking is still pending.
   * Separate from `status` on purpose — a tour can be confirmed and then
   * completed, cancelled or no-showed, and the enum cannot hold both facts.
   */
  confirmedAt: ISODateString | null;
  outcome: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClTourRequest {
  leadId?: string;
  guideUserId?: string;
  scheduledAt: string;
  durationMin?: number;
  status?: ClTourStatus;
  outcome?: string;
  notes?: string;
}

// `confirmedAt` is update-only (see UpdateClTourDto): a tour is booked pending and
// confirmed afterwards. `null` clears a confirmation booked by mistake.
export type UpdateClTourRequest = Partial<CreateClTourRequest> & {
  confirmedAt?: string | null;
};

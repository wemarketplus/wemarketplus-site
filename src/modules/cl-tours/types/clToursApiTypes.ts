import type { ID, ISODateString } from '@/shared/types';
import type { ClTourStatus } from '../constants/clToursApiConstants';
import type { NewTourFormValues } from '../schema/clTourSchema';

// Backend record shapes for CommunityLink tours (wemarketplus-backend cl/tours).
export interface ClTourRecord {
  id: ID;
  tenantId: ID;
  leadId: ID | null;
  guideUserId: ID | null;
  scheduledAt: ISODateString;
  durationMin: number | null;
  status: ClTourStatus;
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

export type UpdateClTourRequest = Partial<CreateClTourRequest>;

// --- Component prop types ---

export interface BookTourModalProps {
  open: boolean;
  isSaving: boolean;
  onClose: () => void;
  // Returns true when the create succeeded, so the form can reset.
  onSubmit: (values: NewTourFormValues) => Promise<boolean>;
}

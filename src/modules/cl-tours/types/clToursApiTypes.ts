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
  /**
   * Where the tour starts and ends — the family's pickup point and the community
   * being shown. Label plus an optional pinned point, in the shape
   * `mileage_logs` uses for a trip's two endpoints.
   *
   * COORDINATES ARRIVE AS STRINGS. The columns are `numeric(10,7)` and the CL
   * controllers return the entity as-is (no response DTO doing the Number()
   * conversion that MileageLogResponseDto does), so the driver's `"38.5816000"`
   * reaches the client verbatim. Typed honestly here rather than as `number`,
   * because `record.fromLat - 1` compiling on a string is how a map ends up
   * drawing a pin in the Gulf of Guinea — go through `tourEndpoint` in
   * clToursUtils, which coerces the pair once.
   */
  fromLocation: string | null;
  fromLat: number | string | null;
  fromLng: number | string | null;
  toLocation: string | null;
  toLat: number | string | null;
  toLng: number | string | null;
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
  /**
   * The tour's two endpoints. `null` CLEARS one (the server's clearable-paired
   * validators accept it and TypeORM writes NULL); omitting the keys leaves the
   * stored value alone, which is what a create wants and what an edit that
   * cleared the field must NOT do.
   *
   * Coordinates go as numbers and only ever in PAIRS — a lone `fromLat` is a
   * 400 by design, since half a point is not a location.
   */
  fromLocation?: string | null;
  fromLat?: number | null;
  fromLng?: number | null;
  toLocation?: string | null;
  toLat?: number | null;
  toLng?: number | null;
}

// `confirmedAt` is update-only (see UpdateClTourDto): a tour is booked pending and
// confirmed afterwards. `null` clears a confirmation booked by mistake.
export type UpdateClTourRequest = Partial<CreateClTourRequest> & {
  confirmedAt?: string | null;
};

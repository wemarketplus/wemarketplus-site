import type { ID, ISODateString } from '@/shared/types';

// Mirrors wemarketplus-backend/src/mileage/entities/mileage-log.entity.ts and its
// create/update DTOs. `date` is a DATE column, so it is a plain YYYY-MM-DD string,
// not an instant — do not pass it through a timezone conversion.
export interface MileageLogRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  date: string;
  fromLocation: string | null;
  toLocation: string | null;
  /**
   * Where the trip's endpoints actually are, from the map picker on the Log-trip
   * form. Null in PAIRS where none was captured — a trip logged before the
   * picker existed, or an endpoint typed by hand — never 0,0, which is a real
   * point in the Gulf of Guinea that a map would happily draw.
   *
   * The label above stays the thing people read; these are what tell two
   * workers' "clinic" apart.
   */
  fromLat: number | null;
  fromLng: number | null;
  toLat: number | null;
  toLng: number | null;
  purpose: string | null;
  miles: number;
  reimbursementRate: number;
  reimbursementAmount: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateMileageLogRequest {
  date?: string;
  fromLocation?: string;
  toLocation?: string;
  /**
   * Sent in PAIRS or not at all — the server's @ValidateIf rejects a lone half
   * with a 400, because a latitude with no longitude is not a location.
   * Coordinates must already be rounded to 7 decimals (the column is
   * numeric(10,7) and the DTO validates maxDecimalPlaces); `roundCoord` in
   * modules/geocoding does it for every value the picker produces.
   */
  fromLat?: number;
  fromLng?: number;
  toLat?: number;
  toLng?: number;
  purpose?: string;
  miles: number;
  reimbursementRate?: number;
}

export type UpdateMileageLogRequest = Partial<CreateMileageLogRequest>;

/** UI state for the field screens. */
export interface FieldUiState {
  /** The EVV log row currently clocked in, so the page can offer clock-out. */
  openVisitId: ID | null;
}

/** Totals over one window, aggregated server-side. */
export interface MileageWindowTotals {
  miles: number;
  reimbursement: number;
  trips: number;
}

/** GET /mileage-logs/summary — the caller's own week and month to date. */
export interface MileageSummary {
  weekToDate: MileageWindowTotals;
  monthToDate: MileageWindowTotals;
}

/** One team member's contribution to the tenant's mileage total. */
export interface TeamMileageMember {
  userId: string;
  /** Null when the user was deleted — the mileage still counts to the total. */
  name: string | null;
  miles: number;
  reimbursement: number;
  trips: number;
}

/**
 * GET /mileage-logs/team-summary — the tenant-wide roll-up for the Admin /
 * Office Manager team page. Admin/Owner only server-side.
 */
export interface TeamMileageSummary {
  weekToDate: MileageWindowTotals;
  monthToDate: MileageWindowTotals;
  /** Month-to-date breakdown, highest mileage first. */
  byUser: TeamMileageMember[];
}

/** Mirrors wemarketplus-backend/src/mileage/mileage.constants.ts ExpenseType. */
export const ExpenseType = {
  Parking: 'parking',
  Tolls: 'tolls',
  Meals: 'meals',
  Supplies: 'supplies',
  Event: 'event',
  Other: 'other',
} as const;
export type ExpenseType = (typeof ExpenseType)[keyof typeof ExpenseType];

export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

/**
 * An expense receipt. Proof of purchase comes in TWO forms and both are live:
 *
 *  - `receiptUrl` — a LINK to a file held elsewhere (Drive, an emailed
 *    statement). Every receipt created before uploads existed uses this, and
 *    those claims are still open, so the link UI stays.
 *  - `hasFile` — a photo/PDF UPLOADED to the server. The bytes are NOT
 *    reachable by URL: they live outside any static root and come back only
 *    from the authenticated, tenant-scoped GET /expense-receipts/:id/file.
 *    That is why there is no path or URL field for them here — see
 *    `utils/receiptFiles.ts` for the fetch.
 *
 * A receipt can carry both (a link from before, a photo attached later).
 */
export interface ExpenseReceiptRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  mileageLogId: ID | null;
  expenseDate: string;
  expenseType: ExpenseType;
  amount: number;
  receiptUrl: string | null;
  receiptFilename: string | null;
  /** True when an uploaded file is attached and downloadable. */
  hasFile: boolean;
  /** Server-SNIFFED MIME type, so the UI can preview an image vs save a PDF. */
  storageMimeType: string | null;
  storageSizeBytes: number | null;
  /** The uploader's original filename, display only. */
  originalFilename: string | null;
  storageUploadedAt: ISODateString | null;
  notes: string | null;
  approvalStatus: ApprovalStatus;
  approvedBy: ID | null;
  approvedAt: ISODateString | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateExpenseReceiptRequest {
  mileageLogId?: string;
  expenseDate: string;
  expenseType: ExpenseType;
  amount: number;
  receiptUrl?: string;
  receiptFilename?: string;
  notes?: string;
}

/**
 * POST /expense-receipts/upload — the receipt row and its photo in ONE
 * multipart request.
 *
 * One request, not create-then-attach: the field worker is on a phone in a car
 * park, and the second call is the one that fails. A two-step flow would
 * routinely leave a claimed amount with no proof, which is the exact state the
 * feature exists to prevent.
 *
 * `file` is sent as-is. The server decides what it actually is from the leading
 * bytes, so the browser's `File.type` guess is advisory here, not a control —
 * do not add client-side "validation" that implies otherwise.
 */
export interface UploadExpenseReceiptRequest {
  mileageLogId?: string;
  expenseDate: string;
  expenseType: ExpenseType;
  amount: number;
  notes?: string;
  file: File;
}

import type { GPSCheckIn } from '@/shared/types';

export type { GPSCheckIn };

/**
 * The two lenses this module still serves.
 *
 * `mileage` was a third: a read-only list built from `cl_outreach_visits.miles`.
 * Mileage now lives on the shared `mileage_logs` screen (modules/field), which is
 * the only one that has the from/to, purpose, IRS-rate reimbursement, receipts and
 * week/month totals the product asks for — so this module keeps the two lenses
 * that are genuinely its own and `/outreach/mileage` redirects there.
 */
export interface ClOutreachUiState {
  view: 'checkin' | 'log';
}

// --- Component prop types ---

export interface CheckInListProps {
  items: readonly GPSCheckIn[];
}

// The UI works directly with the backend ClReferralSourceRecord shape (see
// types/clReferralsApiTypes). No separate view-model is needed — the columns map
// straight onto the record fields (name, type, organization, referralCount,
// lastReferralDate). Kept as a re-export so importers have a single name.
export type { ClReferralSourceRecord as ReferralSource } from './clReferralsApiTypes';

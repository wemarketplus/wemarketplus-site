/**
 * How long a lead may go untouched before Daily Task calls it out.
 *
 * The guide only says "a lead that's gone quiet too long", so the threshold is a
 * product decision made here. 14 days matches the cold-account threshold
 * HospiceLink's daily queue already uses for referral sources, which keeps "quiet"
 * meaning the same span across both products.
 */
export const CL_QUIET_AFTER_DAYS = 14;

/**
 * How many leads / tours the queue loads.
 *
 * Neither endpoint can filter by "follow-up due" or "quiet since", so the
 * selection happens client-side over one page — the same sampling caveat the
 * CommunityLink dashboards carry. Server-side filters (`followUpBefore`,
 * `updatedBefore`) would turn this into a real query.
 */
export const CL_DAILY_TASK_FETCH_LIMIT = 200;

/** Rows shown per section before deferring to the full pipeline. */
export const CL_DAILY_TASK_MAX_ROWS = 10;

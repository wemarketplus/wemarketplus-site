// Backend CommunityLink lead enums — mirror wemarketplus-backend
// communitylink.constants (CareLevel, LeadStage, Urgency, ClLeadLostReason). Distinct from the
// UI-layer LeadStatus in @/shared/types (see leadsConstants for the display map).
export const CL_CARE_LEVEL = {
  IndependentLiving: 'IL',
  AssistedLiving: 'AL',
  MemoryCare: 'MC',
} as const;
export type ClCareLevel = (typeof CL_CARE_LEVEL)[keyof typeof CL_CARE_LEVEL];

export const CL_LEAD_STAGE = {
  Inquiry: 'inquiry',
  Contacted: 'contacted',
  TourScheduled: 'tour_scheduled',
  Toured: 'toured',
  ProposalSent: 'proposal_sent',
  DepositPaid: 'deposit_paid',
  MovedIn: 'moved_in',
  Lost: 'lost',
  Inactive: 'inactive',
} as const;
export type ClLeadStage = (typeof CL_LEAD_STAGE)[keyof typeof CL_LEAD_STAGE];

export const CL_URGENCY = {
  Hot: 'hot',
  Warm: 'warm',
  Cold: 'cold',
} as const;
export type ClUrgency = (typeof CL_URGENCY)[keyof typeof CL_URGENCY];

/**
 * Why a lead was lost — mirrors ClLeadLostReason.
 *
 * Required by the server on entry to `lost`, with free text additionally required
 * when the reason is `other` (see CL_LOST_REASON_REQUIRING_DETAIL below). The
 * server enforces both; this side asks for them so the user is never bounced by a
 * rule the form did not mention.
 */
export const CL_LOST_REASON = {
  Price: 'price',
  Location: 'location',
  ChoseCompetitor: 'chose_competitor',
  ChoseHomeCare: 'chose_home_care',
  Deceased: 'deceased',
  Other: 'other',
} as const;
export type ClLostReason = (typeof CL_LOST_REASON)[keyof typeof CL_LOST_REASON];

/** The one reason that also requires free text. Mirrors the backend constant. */
export const CL_LOST_REASON_REQUIRING_DETAIL = CL_LOST_REASON.Other;

/** Matches the column width and the DTO's @MaxLength. */
export const CL_LOST_REASON_DETAIL_MAX_LENGTH = 500;

/**
 * The three kinds of Resident Care Log entry — mirrors the backend's
 * ClResidentNoteCategory. `undefined`/`null` on a `cl_lead_notes` row is still
 * valid: that is a general Activity Note or a per-lead note, which existed
 * before the Resident Care Log did and keeps working unchanged.
 */
export const CL_RESIDENT_NOTE_CATEGORY = {
  WellnessCheck: 'wellness_check',
  IncidentReport: 'incident_report',
  FamilyUpdate: 'family_update',
} as const;
export type ClResidentNoteCategory =
  (typeof CL_RESIDENT_NOTE_CATEGORY)[keyof typeof CL_RESIDENT_NOTE_CATEGORY];

/** Display labels, mirroring the backend's CL_RESIDENT_NOTE_CATEGORY_LABELS. */
export const CL_RESIDENT_NOTE_CATEGORY_LABELS: Record<ClResidentNoteCategory, string> = {
  [CL_RESIDENT_NOTE_CATEGORY.WellnessCheck]: 'Wellness check',
  [CL_RESIDENT_NOTE_CATEGORY.IncidentReport]: 'Incident note',
  [CL_RESIDENT_NOTE_CATEGORY.FamilyUpdate]: 'Family update',
};

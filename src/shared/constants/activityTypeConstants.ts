// The canonical activity type for any logged interaction. Hand-mirrored from
// wemarketplus-backend/src/common/constants/activity-type.enum.ts — ONE enum,
// shared by notes and appointments on both sides of the wire. If you add a value
// here it also needs an `ALTER TYPE activity_type_enum ADD VALUE` migration; do
// NOT introduce a module-local variant.
//
// This answers "what happened". It is deliberately separate from an appointment's
// `appointmentType` (in person / call / virtual), which is the CHANNEL: a brochure
// drop-off and a lunch-and-learn are both `in_person`, and that
// indistinguishability is exactly what this enum exists to remove.

export const ActivityType = {
  FacilityOfficeVisit: 'facility_office_visit',
  PhysicianProviderMeeting: 'physician_provider_meeting',
  DropOffMarketingMaterials: 'drop_off_marketing_materials',
  LunchLearnMealDropOff: 'lunch_learn_meal_drop_off',
  InServiceStaffPresentation: 'in_service_staff_presentation',
  PhoneCall: 'phone_call',
  Email: 'email',
  TextSms: 'text_sms',
  CommunityEvent: 'community_event',
  VirtualVideoMeeting: 'virtual_video_meeting',
  ThankYouGiftDelivery: 'thank_you_gift_delivery',
  /** Requires `activityTypeOther` free text — the backend 400s without it. */
  Other: 'other',
} as const;
export type ActivityType = (typeof ActivityType)[keyof typeof ActivityType];

/** Display labels, matching the backend's ACTIVITY_TYPE_LABELS exactly. */
export const ACTIVITY_TYPE_LABELS: Record<ActivityType, string> = {
  [ActivityType.FacilityOfficeVisit]: 'Facility / Office Visit',
  [ActivityType.PhysicianProviderMeeting]: 'Physician / Provider Meeting',
  [ActivityType.DropOffMarketingMaterials]: 'Drop-Off — Marketing Materials',
  [ActivityType.LunchLearnMealDropOff]: 'Lunch & Learn / Meal Drop-Off',
  [ActivityType.InServiceStaffPresentation]: 'In-Service / Staff Presentation',
  [ActivityType.PhoneCall]: 'Phone Call',
  [ActivityType.Email]: 'Email',
  [ActivityType.TextSms]: 'Text / SMS',
  [ActivityType.CommunityEvent]: 'Community Event / Health Fair / Conference',
  [ActivityType.VirtualVideoMeeting]: 'Virtual / Video Meeting',
  [ActivityType.ThankYouGiftDelivery]: 'Thank-You / Gift Delivery',
  [ActivityType.Other]: 'Other (free text required)',
};

/** Select options, in the order the product specified. */
export const ACTIVITY_TYPE_OPTIONS = (
  Object.values(ActivityType) as ActivityType[]
).map((value) => ({ value, label: ACTIVITY_TYPE_LABELS[value] }));

/** The one value that makes the free-text field mandatory. */
export const ACTIVITY_TYPE_REQUIRING_DETAIL = ActivityType.Other;

export const ACTIVITY_TYPE_OTHER_MAX_LENGTH = 200;

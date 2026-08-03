import { z } from 'zod';
import {
  ACTIVITY_TYPE_OTHER_MAX_LENGTH,
  ACTIVITY_TYPE_REQUIRING_DETAIL,
  ActivityType,
} from '@/shared/constants/activityTypeConstants';
import { Urgency } from '@/shared/types';

const ACTIVITY_TYPE_VALUES = Object.values(ActivityType) as [
  ActivityType,
  ...ActivityType[],
];

// Create/edit form for a structured note. Mirrors the backend CreateNoteDto
// (wemarketplus-backend/src/notes/dto/create-note.dto.ts). Blank optionals are
// dropped before the request so the DTO never sees empty strings.
//
// Two rules are enforced here as well as server-side, so the user is told before
// the round trip rather than by a 400:
//   * at least one target (prospect / referral source / contact)
//   * free text when the activity type is `other`
export const noteSchema = z
  .object({
    // All three optional individually; the refinement below requires one.
    prospectId: z.string().max(200).optional().or(z.literal('')),
    referralSourceId: z.string().max(200).optional().or(z.literal('')),
    contactId: z.string().max(200).optional().or(z.literal('')),
    summary: z.string().min(1, 'Add a short summary').max(2000),
    activityType: z.enum(ACTIVITY_TYPE_VALUES).optional().or(z.literal('')),
    activityTypeOther: z
      .string()
      .max(ACTIVITY_TYPE_OTHER_MAX_LENGTH)
      .optional()
      .or(z.literal('')),
    /** @deprecated Superseded by `activityType`; kept so older notes still edit. */
    contactType: z.string().max(200).optional().or(z.literal('')),
    urgency: z.enum([Urgency.Hot, Urgency.Warm, Urgency.Cold]),
    patientStatus: z.string().max(200).optional().or(z.literal('')),
    barriers: z.string().max(2000).optional().or(z.literal('')),
    nextStep: z.string().max(500).optional().or(z.literal('')),
    followUpDate: z.string().optional().or(z.literal('')),
  })
  .refine(
    (v) => Boolean(v.prospectId || v.referralSourceId || v.contactId),
    {
      message:
        'A note needs at least one target: a prospect, a referral source or a contact.',
      path: ['prospectId'],
    },
  )
  .refine(
    (v) =>
      v.activityType !== ACTIVITY_TYPE_REQUIRING_DETAIL ||
      Boolean(v.activityTypeOther?.trim()),
    {
      message: 'Describe the activity when the type is “other”.',
      path: ['activityTypeOther'],
    },
  );

export type NoteFormValues = z.infer<typeof noteSchema>;

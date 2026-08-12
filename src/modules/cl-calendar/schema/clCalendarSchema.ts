import { z } from 'zod';

/**
 * The one form behind "schedule a tour, a facility visit, or even a physician
 * lunch".
 *
 * ONE schema with a `kind` discriminator rather than three forms, because the
 * user's decision is "what am I putting on Tuesday?" and the fields barely
 * differ. `superRefine` enforces the per-kind requirements the two backends have:
 * a tour needs an instant (`scheduledAt` is required on POST /cl/tours), a visit
 * needs a date and somewhere to have been.
 */
export const clScheduleSchema = z
  .object({
    kind: z.enum(['tour', 'visit', 'lunch']),
    /** `datetime-local` for a tour; `date` for a visit. */
    when: z.string().min(1, 'Pick a date'),
    // Tour fields.
    leadId: z.string().optional().or(z.literal('')),
    guideUserId: z.string().optional().or(z.literal('')),
    durationMin: z.string().optional().or(z.literal('')),
    // Visit fields.
    locationName: z.string().max(200).optional().or(z.literal('')),
    contactName: z.string().max(200).optional().or(z.literal('')),
    referralSourceId: z.string().optional().or(z.literal('')),
    notes: z.string().max(2000).optional().or(z.literal('')),
  })
  .superRefine((values, ctx) => {
    if (values.kind === 'tour') return;
    // A visit with no location and no referral source is a row nobody can later
    // identify — the Outreach Log would show a date and nothing else.
    if (!values.locationName?.trim() && !values.referralSourceId) {
      ctx.addIssue({
        code: 'custom',
        path: ['locationName'],
        message: 'Name the facility, or pick a referral source',
      });
    }
  });

export type ClScheduleFormValues = z.infer<typeof clScheduleSchema>;

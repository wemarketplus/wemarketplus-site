import { z } from 'zod';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import { LeadSourceType } from '../types/leadsTypes';

const TEXT_MAX = 200;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * New inbound referral. Nothing is strictly required by the backend, but a lead with
 * neither a patient nor a referring organisation is not actionable, so the form
 * requires at least one of the two.
 */
export const newLeadSchema = z
  .object({
    sourceType: z.enum(
      Object.values(LeadSourceType) as [string, ...string[]],
    ),
    sourceDetail: z.string().trim().max(TEXT_MAX).optional().or(z.literal('')),
    patientName: z.string().trim().max(TEXT_MAX).optional().or(z.literal('')),
    /**
     * A date of birth describes something that has ALREADY happened, so a future
     * value is never a plan — it is a typo or a mis-keyed year.
     *
     * This is the layer that catches a date TYPED into the field. `max` on the
     * DatePicker (see AddLeadModal) stops the calendar OFFERING a future day,
     * but the component deliberately keeps an out-of-range typed value rather
     * than silently erasing it, precisely so the form that set the rule is what
     * reports it — see the commitDraft note in DatePicker.
     *
     * Compared as strings: both sides are zero-padded `yyyy-MM-dd`, so `<=` is a
     * correct chronological compare with no Date parsing and therefore no
     * timezone conversion to get wrong. `todayLocalDate()` is called per parse,
     * not captured at module load, so a session left open across midnight moves
     * with the clock. Today itself stays valid.
     */
    patientDob: z
      .string()
      .regex(ISO_DATE, 'Use YYYY-MM-DD')
      .refine(
        // Shape is the regex above's job. Zod 4 runs every check and collects
        // the issues, so without this guard "abc" would report BOTH "Use
        // YYYY-MM-DD" and a nonsensical "in the future".
        (value) => !ISO_DATE.test(value) || value <= todayLocalDate(),
        'Date of birth cannot be in the future',
      )
      .optional()
      .or(z.literal('')),
    diagnosisReason: z.string().trim().max(2000).optional().or(z.literal('')),
    referringPerson: z.string().trim().max(TEXT_MAX).optional().or(z.literal('')),
    referringOrg: z.string().trim().max(TEXT_MAX).optional().or(z.literal('')),
  })
  .refine(
    (values) => Boolean(values.patientName?.trim() || values.referringOrg?.trim()),
    {
      message: 'Enter a patient name or a referring organisation',
      path: ['patientName'],
    },
  );

export type NewLeadFormValues = z.infer<typeof newLeadSchema>;

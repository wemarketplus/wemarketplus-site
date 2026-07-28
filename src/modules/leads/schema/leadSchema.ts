import { z } from 'zod';
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
    patientDob: z
      .string()
      .regex(ISO_DATE, 'Use YYYY-MM-DD')
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

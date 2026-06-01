import { z } from 'zod';
import { PASSWORD_MIN_LENGTH } from '@/modules/auth/constants/authConstants';

export const accountInfoSchema = z
  .object({
    firstName: z.string().min(1, 'Required').max(120),
    lastName: z.string().min(1, 'Required').max(120),
    email: z.string().email('Enter a valid email address'),
    password: z
      .string()
      .min(PASSWORD_MIN_LENGTH, `At least ${PASSWORD_MIN_LENGTH} characters`),
    confirmPassword: z.string(),
  })
  .refine((v) => v.password === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'Passwords must match',
  });
export type AccountInfoFormValues = z.infer<typeof accountInfoSchema>;

export const agencyInfoSchema = z.object({
  agencyName: z.string().min(2, 'Required').max(200),
  city: z.string().min(1, 'Required').max(120),
  state: z.string().length(2, 'Pick a state'),
  phone: z.string().min(7, 'Enter a valid phone').max(40),
  // `valueAsNumber` on the <input> handles the cast — keeping the zod schema
  // simple keeps RHF input/output types aligned (no Resolver mismatch).
  marketerCount: z.number().int().min(1).max(500),
});
export type AgencyInfoFormValues = z.infer<typeof agencyInfoSchema>;

export const baaSchema = z.object({
  signature: z.string().min(2, 'Sign with your full name').max(200),
  title: z.string().min(2, 'Required').max(120),
  acknowledged: z.boolean().refine((v) => v === true, {
    message: 'You must confirm you read the BAA',
  }),
});
export type BAAFormValues = z.infer<typeof baaSchema>;

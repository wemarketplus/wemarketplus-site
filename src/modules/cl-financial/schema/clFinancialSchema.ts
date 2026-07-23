import { z } from 'zod';
import { CONCESSION_STATUS, LEAKAGE_STATUS } from '../constants/clFinancialApiConstants';

const money = (msg: string) =>
  z
    .string()
    .optional()
    .or(z.literal(''))
    .refine((v) => !v || /^\d+(\.\d{1,2})?$/.test(v), msg);

// Revenue ledger entry — mirrors POST /cl/revenue-entries. entryDate + amount
// required (amount collected as a string, parsed on submit).
export const revenueSchema = z.object({
  entryDate: z.string().min(1, 'Pick a date'),
  category: z.string().max(200).optional().or(z.literal('')),
  amount: z.string().min(1, 'Required').regex(/^\d+(\.\d{1,2})?$/, 'Enter an amount like 10800'),
  budgetAmount: money('Enter an amount like 11000'),
  description: z.string().max(2000).optional().or(z.literal('')),
});
export type RevenueFormValues = z.infer<typeof revenueSchema>;

// Concession — mirrors POST /cl/concessions. type required.
export const concessionSchema = z.object({
  type: z.string().min(1, 'Required').max(200),
  valueAmount: money('Enter an amount like 2000'),
  status: z.enum([
    CONCESSION_STATUS.Pending,
    CONCESSION_STATUS.Approved,
    CONCESSION_STATUS.Rejected,
  ]),
  reason: z.string().max(2000).optional().or(z.literal('')),
});
export type ConcessionFormValues = z.infer<typeof concessionSchema>;

// Competitor — mirrors POST /cl/competitors. name required.
export const competitorSchema = z.object({
  name: z.string().min(1, 'Required').max(200),
  city: z.string().max(200).optional().or(z.literal('')),
  distanceMiles: money('Enter miles like 3.5'),
  rateIl: money('Enter a rate like 3800'),
  rateAl: money('Enter a rate like 4800'),
  rateMc: money('Enter a rate like 6200'),
  occupancyPct: money('Enter a percent like 92'),
  notes: z.string().max(2000).optional().or(z.literal('')),
});
export type CompetitorFormValues = z.infer<typeof competitorSchema>;

// LOC pricing — mirrors POST /cl/loc-pricing. level + label + addOnRate required.
export const locSchema = z.object({
  level: z.string().min(1, 'Required').regex(/^\d+$/, 'Whole number'),
  label: z.string().min(1, 'Required').max(200),
  description: z.string().max(2000).optional().or(z.literal('')),
  addOnRate: z.string().min(1, 'Required').regex(/^\d+(\.\d{1,2})?$/, 'Enter an amount like 500'),
});
export type LocFormValues = z.infer<typeof locSchema>;

// Revenue leakage item — mirrors POST /cl/leakage-items. issue + type required.
export const leakageSchema = z.object({
  issue: z.string().min(1, 'Required').max(200),
  type: z.string().min(1, 'Required').max(200),
  monthlyImpact: money('Enter an amount like 380'),
  status: z.enum([
    LEAKAGE_STATUS.Active,
    LEAKAGE_STATUS.Ongoing,
    LEAKAGE_STATUS.Review,
    LEAKAGE_STATUS.FixNeeded,
    LEAKAGE_STATUS.Resolved,
  ]),
  notes: z.string().max(2000).optional().or(z.literal('')),
});
export type LeakageFormValues = z.infer<typeof leakageSchema>;

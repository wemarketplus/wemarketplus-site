import { z } from 'zod';

// Create/edit form for a daily goal. Mirrors the backend CreateGoalDto
// (wemarketplus-backend/src/goals/dto/create-goal.dto.ts): title + targetValue
// are required, targetValue/currentValue are non-negative integers.
const periodValues = ['daily', 'weekly', 'monthly', 'quarterly', 'yearly'] as const;
// What the goal counts. `manual` keeps the original hand-entered behaviour; the
// other three are computed by the backend from real activity.
const metricValues = ['manual', 'visits', 'calls', 'referrals'] as const;

// targetValue/currentValue inputs register with valueAsNumber, so a blank field
// yields NaN. z4's z.number() rejects NaN before .refine runs, so allow it
// through the union then reject it with a "required" message (mirrors
// modules/invoices/schema/invoiceSchema.ts).
export const goalSchema = z.object({
  title: z.string().min(1, 'Title is required').max(300),
  targetValue: z
    .number()
    .int('Whole numbers only')
    .min(0, 'Must be 0 or more')
    .or(z.nan())
    .refine((v) => !Number.isNaN(v), 'Target is required'),
  currentValue: z
    .number()
    .int('Whole numbers only')
    .min(0, 'Must be 0 or more')
    .or(z.nan())
    .refine((v) => !Number.isNaN(v), 'Current is required'),
  unit: z.string().max(50).optional().or(z.literal('')),
  period: z.enum(periodValues),
  metric: z.enum(metricValues),
});

export type GoalFormValues = z.infer<typeof goalSchema>;

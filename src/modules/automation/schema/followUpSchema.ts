import { z } from 'zod';

/**
 * Mirrors the backend CreateFollowUpDto
 * (wemarketplus-backend/src/automation/dto/create-follow-up.dto.ts).
 *
 * Prospect and due date are REQUIRED here for the same reason they are there,
 * restated so the user finds out before the round trip rather than through a
 * 400: an automation with no prospect is just a to-do, and one with no due date
 * can never appear in the Daily tasks queue — which is the entire promise of
 * "so nothing slips".
 *
 * `dueDate` is validated as a shape, not a range. A follow-up dated in the past
 * is legitimate — it lands in the queue immediately as overdue, which is exactly
 * what a marketer catching up on a missed promise wants.
 */
export const followUpSchema = z.object({
  prospectId: z.string().min(1, 'Choose a prospect'),
  title: z.string().min(1, 'Say what to do').max(300),
  dueDate: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Choose a due date'),
  cadenceNote: z.string().max(500).optional().or(z.literal('')),
});

export type FollowUpFormValues = z.infer<typeof followUpSchema>;

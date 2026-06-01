import { z } from 'zod';
import {
  NAME_MAX_LENGTH,
  NAME_MIN_LENGTH,
} from '@/modules/users/constants/usersConstants';

// PATCH /users/me — mirrors UpdateOwnProfileRequest.
export const profileSchema = z.object({
  firstName: z.string().min(NAME_MIN_LENGTH).max(NAME_MAX_LENGTH),
  lastName: z.string().min(NAME_MIN_LENGTH).max(NAME_MAX_LENGTH),
  email: z.string().email('Enter a valid email address'),
});

export type ProfileFormValues = z.infer<typeof profileSchema>;

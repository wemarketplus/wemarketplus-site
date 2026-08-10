import { z } from 'zod';
import {
  NAME_MAX_LENGTH,
  NAME_MIN_LENGTH,
  PHONE_MAX_LENGTH,
} from '@/modules/users/constants/usersConstants';

// PATCH /users/me — mirrors UpdateOwnProfileRequest.
export const profileSchema = z.object({
  firstName: z.string().min(NAME_MIN_LENGTH).max(NAME_MAX_LENGTH),
  lastName: z.string().min(NAME_MIN_LENGTH).max(NAME_MAX_LENGTH),
  email: z.string().email('Enter a valid email address'),
  // Optional and free-form, matching the backend DTO: extensions and
  // international prefixes are real, so a format rule would only reject valid
  // numbers. An empty string is a legitimate "I have no phone number" and the
  // hook maps it to an empty patch field rather than failing validation.
  phone: z.string().max(PHONE_MAX_LENGTH),
});

export type ProfileFormValues = z.infer<typeof profileSchema>;

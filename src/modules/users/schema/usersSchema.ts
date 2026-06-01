import { z } from 'zod';
import { Role } from '@/shared/rbac';
import {
  NAME_MAX_LENGTH,
  NAME_MIN_LENGTH,
  PASSWORD_MIN_LENGTH,
} from '../constants/usersConstants';

const nameField = z
  .string()
  .min(NAME_MIN_LENGTH, 'Required')
  .max(NAME_MAX_LENGTH, `At most ${NAME_MAX_LENGTH} characters`);

const roleField = z.enum([Role.Admin, Role.Manager, Role.Rep]);

export const createUserSchema = z.object({
  email: z.string().email('Enter a valid email address'),
  password: z
    .string()
    .min(PASSWORD_MIN_LENGTH, `At least ${PASSWORD_MIN_LENGTH} characters`),
  firstName: nameField,
  lastName: nameField,
  role: roleField,
});

export type CreateUserFormValues = z.infer<typeof createUserSchema>;

export const updateUserSchema = z.object({
  email: z.string().email('Enter a valid email address').optional(),
  firstName: nameField.optional(),
  lastName: nameField.optional(),
  role: roleField.optional(),
});

export type UpdateUserFormValues = z.infer<typeof updateUserSchema>;

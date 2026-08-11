import { z } from 'zod';
import {
  ASSIGNABLE_ROLES,
  NAME_MAX_LENGTH,
  NAME_MIN_LENGTH,
  PASSWORD_MIN_LENGTH,
} from '../constants/usersConstants';

const nameField = z
  .string()
  .min(NAME_MIN_LENGTH, 'Required')
  .max(NAME_MAX_LENGTH, `At most ${NAME_MAX_LENGTH} characters`);

// Every backend-assignable role except super_admin (platform-only) — mirrors
// wemarketplus-backend/src/users/dto/create-user.dto.ts.
const roleField = z.enum(ASSIGNABLE_ROLES);

// Mirrors the POST /users body (CreateUserRequest).
export const createUserSchema = z.object({
  email: z.string().email('Enter a valid email address'),
  password: z
    .string()
    .min(PASSWORD_MIN_LENGTH, `At least ${PASSWORD_MIN_LENGTH} characters`),
  firstName: nameField,
  lastName: nameField,
  role: roleField,
  // A custom role id, or '' for "standard role". Kept as a plain string rather than a
  // uuid check: the value always comes from a <select> of the tenant's own roles.
  customRoleId: z.string().optional(),
});

export type CreateUserFormValues = z.infer<typeof createUserSchema>;

// Add User form — the DTO fields plus the UI-only "email an invite" toggle,
// which drives a follow-up POST /invites rather than a request body field.
export const newUserSchema = createUserSchema.extend({
  sendInvite: z.boolean(),
});

export type NewUserFormValues = z.infer<typeof newUserSchema>;

export const updateUserSchema = z.object({
  email: z.string().email('Enter a valid email address').optional(),
  firstName: nameField.optional(),
  lastName: nameField.optional(),
  role: roleField.optional(),
  customRoleId: z.string().nullable().optional(),
});

export type UpdateUserFormValues = z.infer<typeof updateUserSchema>;

// Edit User form — the fields an admin can change from the row action modal:
// name, role, and the active flag. Email stays read-only here (changing it has
// verification implications handled elsewhere), matching the Add form's split.
export const editUserSchema = z.object({
  firstName: nameField,
  lastName: nameField,
  role: roleField,
  // '' means "no custom role" and is sent as null, which CLEARS an existing
  // assignment — unlike create, where blank simply omits the field.
  customRoleId: z.string().optional(),
  isActive: z.boolean(),
});

export type EditUserFormValues = z.infer<typeof editUserSchema>;

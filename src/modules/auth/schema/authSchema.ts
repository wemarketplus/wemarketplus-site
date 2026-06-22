import { z } from 'zod';
import { NAME_MAX_LENGTH, NAME_MIN_LENGTH, PASSWORD_MIN_LENGTH } from '../constants/authConstants';

const emailField = z.string().email('Enter a valid email address');
const passwordField = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters`);

// --- Login ---
export const loginSchema = z.object({
  email: emailField,
  password: passwordField,
});
export type LoginFormValues = z.infer<typeof loginSchema>;

// --- Register ---
// Self-registration provisions a new tenant, so organizationName is required
// to match the backend RegisterDto.
export const registerSchema = loginSchema.extend({
  firstName: z.string().min(NAME_MIN_LENGTH).max(NAME_MAX_LENGTH),
  lastName: z.string().min(NAME_MIN_LENGTH).max(NAME_MAX_LENGTH),
  organizationName: z.string().min(2).max(120),
});
export type RegisterFormValues = z.infer<typeof registerSchema>;

// --- Forgot password ---
export const forgotPasswordSchema = z.object({
  email: emailField,
});
export type ForgotPasswordFormValues = z.infer<typeof forgotPasswordSchema>;

// --- Reset / Change / Accept-invite ---
// Single shape — all three are "pick a new password and confirm" forms. The
// page-level forms add a token (reset/accept-invite) or current password
// (change-password) on top before submitting.
const newPasswordShape = z
  .object({
    password: passwordField,
    confirmPassword: z.string(),
  })
  .refine((v) => v.password === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'Passwords must match',
  });

export const resetPasswordSchema = newPasswordShape;
export type ResetPasswordFormValues = z.infer<typeof resetPasswordSchema>;

export const acceptInviteSchema = newPasswordShape;
export type AcceptInviteFormValues = z.infer<typeof acceptInviteSchema>;

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1, 'Required'),
    password: passwordField,
    confirmPassword: z.string(),
  })
  .refine((v) => v.password === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'Passwords must match',
  });
export type ChangePasswordFormValues = z.infer<typeof changePasswordSchema>;

import type { ReactNode } from 'react';
import type { Role } from '@/shared/rbac';
import type { ISODateString, ID, Product, Tier } from '@/shared/types';

// Mirrors wemarketplus-backend/src/users/dto/user-response.dto.ts. The
// product/tier fields aren't shipped by the backend yet — they're optional
// here so the UI can fall back to defaults via the auth slice.
export interface AuthenticatedUser {
  id: ID;
  tenantId: ID;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
  phone: string | null;
  avatarUrl: string | null;
  isActive: boolean;
  createdAt: ISODateString;
  updatedAt: ISODateString;
  // TODO(backend): expose these on /auth/me when product/tier ship.
  product?: Product;
  tier?: Tier;
}

// Mirrors wemarketplus-backend/src/auth/dto/auth-response.dto.ts:
// { accessToken, refreshToken?, user }.
export interface LoginResponse {
  accessToken: string;
  refreshToken?: string;
  user: AuthenticatedUser;
}

export interface LoginRequest {
  email: string;
  password: string;
}

// Self-registration provisions a new tenant, so the backend RegisterDto
// requires organizationName.
export interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  organizationName: string;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

// --- Password flows ---

export interface ForgotPasswordRequest {
  email: string;
}

// Backend ResetPasswordDto uses `newPassword` (not `password`).
export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}

// Backend POST /invites/accept consumes a token only — it marks the invite
// accepted and returns the invite record. It does NOT set a password or log
// the user in (no /auth/accept-invite exists today).
export interface AcceptInviteRequest {
  token: string;
}

export interface AcceptInviteResponse {
  id: ID;
  email: string;
  role: Role;
  acceptedAt: ISODateString | null;
}

// Backend ChangePasswordDto uses `newPassword` (not `password`).
export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

// The change-password form collects `password`; the hook maps it to the
// backend's `newPassword` before calling the API.
export interface ChangePasswordFormInput {
  currentPassword: string;
  password: string;
}

// --- Slice state ---

export interface AuthState {
  token: string | null;
  refreshToken: string | null;
  user: AuthenticatedUser | null;
  isAuthenticated: boolean;
}

// --- Component prop types ---

export interface AuthCardShellProps {
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  product?: Product;
  hideFooter?: boolean;
  maxWidth?: 420 | 440;
}

export interface AuthErrorProps {
  children?: ReactNode;
}

export interface AuthFieldProps {
  label: string;
  htmlFor: string;
  error?: string;
  children: ReactNode;
  helper?: ReactNode;
}

export interface PasswordStrengthMeterProps {
  value: string;
}

// --- Password strength types ---

export interface Rule {
  key: string;
  label: string;
  test: (v: string) => boolean;
}

export type Strength = 'none' | 'weak' | 'mid' | 'strong';

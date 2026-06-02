import type { ReactNode } from 'react';
import type { Role } from '@/shared/rbac';
import type { ISODateString, ID, Product, Tier } from '@/shared/types';

// Mirrors wemarketplus-backend/src/users/dto/user-response.dto.ts. The
// product/tier fields aren't shipped by the backend yet — they're optional
// here so the UI can fall back to defaults via the auth slice.
export interface AuthenticatedUser {
  id: ID;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
  createdAt: ISODateString;
  updatedAt: ISODateString;
  // TODO(backend): expose these on /auth/me when product/tier ship.
  product?: Product;
  tier?: Tier;
}

// Mirrors wemarketplus-backend/src/auth/dto/auth-response.dto.ts.
export interface LoginResponse {
  accessToken: string;
  user: AuthenticatedUser;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

// --- Password flows (backend endpoints pending) ---

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  token: string;
  password: string;
}

export interface AcceptInviteRequest {
  token: string;
  password: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  password: string;
}

// --- Slice state ---

export interface AuthState {
  token: string | null;
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

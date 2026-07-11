import type { ReactNode } from 'react';
import type { Role } from '@/shared/rbac';
import type { ISODateString, ID, Product } from '@/shared/types';

// Mirrors wemarketplus-backend/src/users/dto/user-response.dto.ts. The tenant
// plan fields (product/tier/organizationName) ship on /auth/me and login
// responses; they stay optional so plain user listings still fit this shape.
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
  // False until the user clicks the verification link (production enforces
  // this before login; dev environments may skip it).
  emailVerified?: boolean;
  // Whether TOTP two-factor auth is enabled. Ships on /auth/me; the Security
  // tab reads it to show status and toggle the enable/disable flow.
  mfaEnabled?: boolean;
  createdAt: ISODateString;
  updatedAt: ISODateString;
  // `tier` is the raw backend CrmTier (may be cl_-prefixed for CommunityLink);
  // normalize via normalizeTier() before comparing against the UI Tier enum.
  product?: Product;
  tier?: string;
  organizationName?: string;
  // The tenant's live billing state ('active' | 'trialing' | 'incomplete' |
  // 'past_due' | 'canceled' | 'suspended'). Ships on /auth/me and login. Used
  // to tell a paid plan from an unpaid signup — e.g. don't show a plan pill
  // until the subscription is active/trialing.
  subscriptionStatus?: string;
}

// Mirrors wemarketplus-backend/src/auth/dto/auth-response.dto.ts:
// { accessToken?, refreshToken?, user?, requiresEmailVerification?,
//   mfaRequired?, mfaToken? }.
// Tokens are absent on register when email verification is enforced
// (production) — the user must verify via /auth/verify-email first. They are
// also absent when the user has MFA enabled: login returns mfaRequired +
// mfaToken and the client must complete POST /auth/mfa/verify.
export interface LoginResponse {
  accessToken?: string;
  refreshToken?: string;
  // Absent on the MFA-required response; present otherwise.
  user?: AuthenticatedUser;
  requiresEmailVerification?: boolean;
  // Set when MFA is enabled: no tokens yet — complete the second step with the
  // 6-digit code and `mfaToken`.
  mfaRequired?: boolean;
  // Short-lived signed token identifying the user for POST /auth/mfa/verify.
  mfaToken?: string;
}

// Register shares the login response shape (including the verification-pending
// variant without tokens).
export type RegisterResponse = LoginResponse;

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

// Backend POST /invites/accept consumes the token AND sets the invitee's
// password (and marks the email verified), returning the user but NO session
// tokens. The client then redirects to /login so the teammate signs in through
// the normal flow (OWASP: don't auto-login off an emailed link).
export interface AcceptInviteRequest {
  token: string;
  password: string;
}

// --- Email verification ---

// POST /auth/verify-email — consumes the emailed token and marks the address
// verified, returning the user but NO session tokens (the client redirects to
// /login). 401 on invalid/expired/reused tokens.
export interface VerifyEmailRequest {
  token: string;
}

// POST /auth/resend-verification — 202 always (enumeration-safe).
export interface ResendVerificationRequest {
  email: string;
}

// Backend ChangePasswordDto uses `newPassword` (not `password`).
export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

// --- MFA (TOTP two-factor) ---

// POST /auth/mfa/setup -> generates a pending secret and returns the enrolment
// payload for the authenticator app (auth-required, no body).
export interface MfaSetupResponse {
  otpauthUrl: string;
  // data: URL PNG of the QR code, ready for an <img src>.
  qrDataUrl: string;
  secret: string;
}

// POST /auth/mfa/enable — confirms the pending secret with a live code (204).
export interface MfaEnableRequest {
  code: string;
}

// POST /auth/mfa/disable — verifies a code OR the account password (204).
export interface MfaDisableRequest {
  code?: string;
  password?: string;
}

// POST /auth/mfa/verify — second login step: exchanges the mfaToken + code for
// real tokens (returns a full LoginResponse).
export interface MfaVerifyRequest {
  mfaToken: string;
  code: string;
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

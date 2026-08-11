import type { ReactNode } from 'react';
import type { CustomRole, Role } from '@/shared/rbac';
import type {
  ISODateString,
  ID,
  Product,
  ProductEntitlement,
} from '@/shared/types';

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
  /**
   * The tenant-defined job title this user holds, if any. `role` above stays the
   * ENFORCED role (always the custom role's baseRole); this narrows the sidebar and
   * relabels the user's title. Ships on /auth/me and login. Absent for the vast
   * majority of users, who hold a plain role.
   */
  customRoleId?: string | null;
  customRole?: CustomRole;
  phone: string | null;
  avatarUrl: string | null;
  // The user's chosen shared-calendar colour ('#rrggbb'), or null to fall back
  // to the colour derived from the id. Ships on /auth/me AND on login, so the
  // calendar and the profile picker both have it with no extra request.
  // Optional so an older backend (or a plain user listing) still fits.
  calendarColor?: string | null;
  isActive: boolean;
  // False until the user clicks the verification link (production enforces
  // this before login; dev environments may skip it).
  emailVerified?: boolean;
  /**
   * True while this user still holds a password an administrator chose for them —
   * an admin-created account or an admin reset. Ships on login and /auth/me.
   *
   * ProtectedRoute sends such a user to /change-password and keeps them there. The
   * real enforcement is the backend's PasswordChangeGuard, which 403s every other
   * endpoint; this flag only lets the UI explain why instead of showing a wall of
   * failed requests. Optional so an older backend still satisfies the type.
   */
  mustChangePassword?: boolean;
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
  // Every product this tenant can use, each with its own tier. Ships on
  // /auth/me and login. `product`/`tier` above remain the primary product; this
  // array drives the product/dashboard switcher (shown only when length > 1).
  // Absent on older backends — callers fall back to the single `product`.
  entitlements?: ProductEntitlement[];
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

// Backend POST /invites/accept consumes the token, sets the invitee's
// password, marks the email verified, and returns the same auth payload used
// by login so the client can immediately establish a session.
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

import type { ID, ISODateString } from '@/shared/types';

/** A revocable per-facility submission link. Mirrors PortalLinkResponseDto. */
export interface PortalLink {
  id: ID;
  referralSourceId: ID;
  /**
   * The URL secret. Shown so an admin can copy or reprint a LIVE link; null once
   * the link is revoked or expired, because a dead link has nothing to copy.
   * Mirrors PortalLinkResponseDto.token — see its doc.
   */
  token: string | null;
  label: string | null;
  isActive: boolean;
  expiresAt: ISODateString | null;
  submissionCount: number;
  lastSubmissionAt: ISODateString | null;
  createdAt: ISODateString;
}

export interface PortalLinkQr {
  url: string;
  /** `data:image/png;base64,…` — rendered server-side by the `qrcode` package. */
  qrDataUrl: string;
}

export interface CreatePortalLinkRequest {
  referralSourceId: string;
  label?: string;
  expiresAt?: string;
}

export interface UpdatePortalLinkRequest {
  isActive?: boolean;
  label?: string;
}

/**
 * All a public visitor is told before submitting: who they are referring to.
 * No ids, no counts, no patient data.
 */
export interface PortalContext {
  organizationName: string;
  facilityName: string;
}

/** The public form body. Only the patient's name is required. */
export interface SubmitPortalReferralRequest {
  patientName: string;
  referringPerson?: string;
  diagnosisReason?: string;
}

/** An acknowledgement, deliberately carrying no record back. */
export interface PortalSubmissionReceipt {
  received: true;
  message: string;
}

// Shared types for the CommunityLink demo design system. Types only — no
// runtime code (per the enforced modular architecture).

// Badge tone keys — mirror the reference's .bg/.ba/.bb/.br/.bx classes.
export type BadgeTone = 'green' | 'amber' | 'blue' | 'red' | 'neutral';

export interface ToastState {
  message: string;
  error: boolean;
  // Bumped on every toast so the autohide effect re-runs even for an
  // identical message (mirrors the reference's re-triggerable T()).
  nonce: number;
}

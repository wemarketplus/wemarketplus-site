import type { PlaybookKind } from '../types/aiTypes';

/**
 * The four playbook shapes. Mirrors the backend PlaybookKind enum — a closed set
 * rather than free text, because each value selects a different OUTPUT shape and
 * letting the user describe the shape in prose is a prompt-injection surface.
 */
export const PLAYBOOK_KIND_OPTIONS: ReadonlyArray<{
  value: PlaybookKind;
  label: string;
}> = [
  { value: 'script', label: 'Call or visit script' },
  { value: 'sop', label: 'Internal SOP' },
  { value: 'referral_strategy', label: 'Referral strategy for an account' },
  { value: 'situation_guidance', label: 'Guidance for a situation' },
];

/** Concrete examples, so the first thing a user types is specific enough to work. */
export const PLAYBOOK_PLACEHOLDERS: Record<PlaybookKind, string> = {
  script:
    'Calling a hospitalist who keeps saying "it is too early for hospice"',
  sop: 'What our team does when a referral arrives by fax after 5pm',
  referral_strategy:
    'Mercy General oncology — we get two referrals a quarter and want more',
  situation_guidance:
    'A SNF director of nursing told us they already use another hospice',
};

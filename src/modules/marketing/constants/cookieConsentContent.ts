// Copy + storage contract for the bottom-of-page cookie consent banner.
// Kept out of the component per the module's constants-not-inline rule.
export const COOKIE_CONSENT_STORAGE_KEY = 'wmp:cookie-consent';

export type CookieConsentChoice = 'accepted' | 'declined';

export const COOKIE_CONSENT_CONTENT = {
  emoji: '🍪',
  message:
    'We use essential cookies for authentication and session management. We do not use tracking cookies.',
  privacyLabel: 'Privacy Policy',
  privacyHref: '/privacy',
  acceptLabel: 'Accept',
  declineLabel: 'Decline Non-Essential',
} as const;

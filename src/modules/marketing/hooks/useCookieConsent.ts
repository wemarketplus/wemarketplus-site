import { useCallback, useEffect, useState } from 'react';
import {
  COOKIE_CONSENT_STORAGE_KEY,
  type CookieConsentChoice,
} from '../constants/cookieConsentContent';

// Drives the cookie consent banner: hidden until we've confirmed the visitor
// hasn't already chosen, then persists their choice so it never re-appears.
// Reads localStorage in an effect (not during render) so SSR/first paint stay
// stable and a blocked storage API degrades gracefully.
export function useCookieConsent() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    try {
      if (!window.localStorage.getItem(COOKIE_CONSENT_STORAGE_KEY)) {
        setVisible(true);
      }
    } catch {
      // localStorage unavailable (private mode, blocked) — show the banner.
      setVisible(true);
    }
  }, []);

  const choose = useCallback((choice: CookieConsentChoice) => {
    try {
      window.localStorage.setItem(COOKIE_CONSENT_STORAGE_KEY, choice);
    } catch {
      // Ignore — we still dismiss for this session.
    }
    setVisible(false);
  }, []);

  return { visible, accept: () => choose('accepted'), decline: () => choose('declined') };
}

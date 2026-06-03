import { Link } from 'react-router-dom';
import { COOKIE_CONSENT_CONTENT } from '../constants/cookieConsentContent';
import { useCookieConsent } from '../hooks/useCookieConsent';

const {
  emoji,
  message,
  privacyLabel,
  privacyHref,
  acceptLabel,
  declineLabel,
} = COOKIE_CONSENT_CONTENT;

// Fixed bottom-of-page cookie consent bar — navy band with a faint top border,
// essential-cookies notice + amber Privacy Policy link on the left, and an
// amber Accept pill plus an outlined "Decline Non-Essential" pill on the right.
export function CookieConsentBanner() {
  const { visible, accept, decline } = useCookieConsent();

  if (!visible) return null;

  return (
    <div
      role="region"
      aria-label="Cookie consent"
      className="fixed inset-x-0 bottom-0 z-[400] border-t border-white/10 bg-[#0a1424]"
    >
      {/* Notice on the LEFT, buttons on the RIGHT (justify-between → first
          child hugs the left edge, second hugs the right). */}
      <div className="flex w-full flex-col items-start gap-3 px-6 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
        <p className="text-[13px] leading-[1.55] text-[#c3cee0]">
          <span className="mr-1.5">{emoji}</span>
          {message}{' '}
          <Link
            to={privacyHref}
            className="font-medium text-[#f59e0b] transition-colors hover:text-[#ffb733] hover:underline"
          >
            {privacyLabel}
          </Link>
        </p>

        <div className="flex flex-shrink-0 items-center gap-2.5">
          <button
            type="button"
            onClick={accept}
            className="rounded-pill bg-[#f59e0b] px-6 py-2 text-[13px] font-bold text-[#06080e] transition-opacity duration-150 hover:opacity-[0.88]"
          >
            {acceptLabel}
          </button>
          <button
            type="button"
            onClick={decline}
            className="whitespace-nowrap rounded-pill border border-white/15 bg-white/[0.04] px-6 py-2 text-[13px] font-semibold text-[#c3cee0] transition-colors duration-150 hover:border-white/30 hover:text-white"
          >
            {declineLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

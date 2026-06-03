import { STRIPE_URL, SUBTITLE } from '../constants/maxNav';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces the reference .topbar: 52px bar with the live page title +
// subtitle, and the amber "Subscribe to Max CRM" CTA (opens Stripe checkout).
export function MaxTopbar() {
  const { pageTitle } = useMaxDemo();

  return (
    <div className="flex h-[52px] flex-shrink-0 items-center justify-between border-b border-white/[0.07] bg-[#060e1b] px-5">
      <div>
        <div className="text-[15px] font-extrabold text-[#f4f8ff]">{pageTitle}</div>
        <div className="text-[11px] text-[#4b6278]">{SUBTITLE}</div>
      </div>
      <a
        href={STRIPE_URL}
        target="_blank"
        rel="noreferrer"
        className="whitespace-nowrap rounded-full bg-gradient-to-br from-[#f59e0b] to-[#d97706] px-[18px] py-[7px] text-[12px] font-extrabold text-[#06080e] no-underline"
      >
        Subscribe to Max CRM
      </a>
    </div>
  );
}

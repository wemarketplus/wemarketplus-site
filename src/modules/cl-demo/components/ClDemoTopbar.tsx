import { PRICING_HREF, SUBTITLE, TAB_TITLES } from '../constants/clDemoNav';
import { useClDemo } from '../hooks/useClDemo';

// Reproduces the reference .topbar: 52px bar with the active page title +
// "Sunrise Senior Living — February 2026" subtitle, and the amber
// "Subscribe to Pro CRM" CTA.
export function ClDemoTopbar() {
  const { activeTab } = useClDemo();

  return (
    <div className="flex h-[52px] flex-shrink-0 items-center justify-between border-b border-white/[0.07] bg-[#060e1b] px-5">
      <div>
        <div className="text-[15px] font-extrabold text-[#f4f8ff]">{TAB_TITLES[activeTab]}</div>
        <div className="text-[11px] text-[#4b6278]">{SUBTITLE}</div>
      </div>
      <a
        href={PRICING_HREF}
        target="_blank"
        rel="noreferrer"
        className="rounded-full bg-gradient-to-br from-[#f59e0b] to-[#d97706] px-[18px] py-[7px] text-[12px] font-extrabold text-[#06080e] no-underline"
      >
        Subscribe to Pro CRM
      </a>
    </div>
  );
}

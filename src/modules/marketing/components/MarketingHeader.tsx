import { Phone } from 'lucide-react';
import { Link } from 'react-router-dom';
import { COMMUNITYLINK_DEMO_URLS } from '@/shared/config/demoUrls';
import { BrandLogo } from './BrandLogo';

// A dropdown target is internal (react-router) unless it points at an
// absolute URL, in which case it must render as a plain anchor.
const isExternal = (to: string) => /^https?:\/\//.test(to);

// Top nav — mirrors the live wemarketplus.com nav exactly: 64px bar, 13px
// text-2 links with a hover surface, "▾" hover dropdowns under HospiceLink /
// CommunityLink, a faint phone number, a thin divider, and the sage Log In
// pill (.nav-login).
const linkCls =
  'rounded-[8px] px-3 py-1.5 transition-colors duration-150 hover:bg-white/[0.03] hover:text-foreground';

type DropItem = { label: string; to: string };

const HOSPICE_MENU: DropItem[] = [
  { label: 'Platform', to: '/#preview' },
  { label: 'Features', to: '/#features' },
  { label: 'Pricing', to: '/#pricing' },
  { label: 'Pro Demo', to: COMMUNITYLINK_DEMO_URLS.pro },
  { label: 'Max Demo', to: COMMUNITYLINK_DEMO_URLS.max },
  { label: 'Gold Demo', to: COMMUNITYLINK_DEMO_URLS.gold },
];

const COMMUNITY_MENU: DropItem[] = [
  { label: 'Overview', to: '/#communitylink' },
  { label: 'Pricing', to: '/#cl-pricing' },
  { label: 'Pricing Page', to: '/communitylink/pricing' },
  { label: 'Pro Demo', to: '/demo/communitylink/pro' },
  { label: 'Gold Demo', to: '/demo/communitylink/gold' },
  { label: 'Max Demo', to: '/demo/communitylink/max' },
];

function NavDropdown({
  label,
  to,
  items,
  accent,
}: {
  label: string;
  to: string;
  items: DropItem[];
  accent?: DropItem;
}) {
  return (
    <div className="group relative">
      <Link to={to} className={linkCls}>
        {label} ▾
      </Link>
      <div className="invisible absolute left-1/2 top-[calc(100%+8px)] z-[9999] min-w-[170px] -translate-x-1/2 rounded-[12px] border border-white/10 bg-[#0d1b2e] p-2 opacity-0 shadow-[0_16px_40px_rgba(0,0,0,0.5)] transition-[opacity,visibility] duration-150 group-hover:visible group-hover:opacity-100">
        {items.map((item) => {
          const itemCls =
            'block whitespace-nowrap rounded-[8px] px-3.5 py-[7px] text-[13px] text-[#c8d6e8] transition-colors hover:bg-white/[0.07] hover:text-white';
          return isExternal(item.to) ? (
            <a key={item.label + item.to} href={item.to} className={itemCls}>
              {item.label}
            </a>
          ) : (
            <Link key={item.label + item.to} to={item.to} className={itemCls}>
              {item.label}
            </Link>
          );
        })}
        {accent ? (
          <Link
            to={accent.to}
            className="block whitespace-nowrap rounded-[8px] px-3.5 py-[7px] text-[13px] font-bold text-amber transition-colors hover:bg-white/[0.07]"
          >
            {accent.label}
          </Link>
        ) : null}
      </div>
    </div>
  );
}

export function MarketingHeader() {
  return (
    <header className="sticky top-0 z-[300] border-b border-white/[0.08] bg-bg/[0.94] backdrop-blur-2xl">
      <div className="mx-auto flex h-16 max-w-[1200px] items-center justify-between px-7">
        <Link
          to="/"
          aria-label="We Market Plus home"
          className="flex items-center transition-opacity duration-150 hover:opacity-90"
        >
          <BrandLogo />
        </Link>

        <nav className="hidden items-center gap-0.5 text-[13px] font-medium text-muted md:flex">
          <NavDropdown label="HospiceLink" to="/#hospicelink" items={HOSPICE_MENU} />
          <NavDropdown
            label="CommunityLink"
            to="/#communitylink"
            items={COMMUNITY_MENU}
            accent={{ label: 'CL Login →', to: '/cl-login' }}
          />
          <Link to="/#faq" className={linkCls}>
            FAQ
          </Link>
          <Link to="/#security" className={linkCls}>
            Security
          </Link>
          <Link to="/#contact" className={linkCls}>
            Contact
          </Link>
          <a
            href="tel:+19725550100"
            className="inline-flex items-center gap-1.5 rounded-[8px] px-2.5 py-1.5 text-[12px] font-semibold text-faint transition-colors duration-150 hover:text-foreground"
          >
            <Phone className="h-[13px] w-[13px]" strokeWidth={2} /> (972) 555-0100
          </a>
          <span className="mx-1 h-5 w-px bg-white/[0.08]" />
          <Link
            to="/login"
            className="rounded-pill bg-sage px-[18px] py-[7px] text-[13px] font-bold text-[#06080e] transition-opacity duration-150 hover:opacity-[0.85]"
          >
            Log In
          </Link>
        </nav>

        {/* Mobile: just the Log In pill until the hamburger menu is wired. */}
        <Link
          to="/login"
          className="rounded-pill bg-sage px-[18px] py-[7px] text-[13px] font-bold text-[#06080e] transition-opacity duration-150 hover:opacity-[0.85] md:hidden"
        >
          Log In
        </Link>
      </div>
    </header>
  );
}

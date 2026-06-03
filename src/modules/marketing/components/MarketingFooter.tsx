import { Layers } from 'lucide-react';
import { Link } from 'react-router-dom';
import { COMMUNITYLINK_DEMO_URLS } from '@/shared/config/demoUrls';

// index.html <footer> — #030508 band, 2fr/1fr/1fr/1fr columns (brand +
// HospiceLink / CommunityLink / Legal / Contact), and a split bottom bar.
type FooterLink = { label: string; to: string };

const COLUMNS: { heading: string; links: FooterLink[] }[] = [
  {
    heading: 'HospiceLink',
    links: [
      { label: 'Platform', to: '/#preview' },
      { label: 'Features', to: '/#features' },
      { label: 'Pricing', to: '/#pricing' },
      { label: 'Pro Demo', to: COMMUNITYLINK_DEMO_URLS.pro },
      { label: 'Max Demo', to: COMMUNITYLINK_DEMO_URLS.max },
      { label: 'Gold Demo', to: COMMUNITYLINK_DEMO_URLS.gold },
      { label: 'Log In', to: '/login' },
    ],
  },
  {
    heading: 'CommunityLink',
    links: [
      { label: 'Overview', to: '/#communitylink' },
      { label: 'Pricing', to: '/#cl-pricing' },
      { label: 'Pro Demo', to: '/demo/communitylink/pro' },
      { label: 'Gold Demo', to: '/demo/communitylink/gold' },
      { label: 'Max Demo', to: '/demo/communitylink/max' },
      { label: 'View Demo', to: '/demo/communitylink/max' },
    ],
  },
  {
    heading: 'Legal',
    links: [
      { label: 'BAA Terms', to: '/#baa' },
      { label: 'Security & HIPAA', to: '/#security' },
      { label: 'Terms of Service', to: '/terms' },
      { label: 'Privacy Policy', to: '/privacy' },
    ],
  },
  {
    heading: 'Contact',
    links: [
      { label: 'info@wemarketplus.com', to: 'mailto:info@wemarketplus.com' },
      { label: '(469) 793-0673', to: 'tel:+14697930673' },
      { label: 'Support', to: 'mailto:info@wemarketplus.com' },
      { label: 'Annual Pricing', to: 'mailto:info@wemarketplus.com' },
    ],
  },
];

function FooterAnchor({ link }: { link: FooterLink }) {
  const cls =
    'block text-[13px] text-faint transition-colors hover:text-foreground';
  if (
    link.to.startsWith('mailto:') ||
    link.to.startsWith('tel:') ||
    /^https?:\/\//.test(link.to)
  ) {
    return (
      <a href={link.to} className={cls}>
        {link.label}
      </a>
    );
  }
  return (
    <Link to={link.to} className={cls}>
      {link.label}
    </Link>
  );
}

export function MarketingFooter() {
  return (
    <footer className="mt-20 border-t border-white/[0.08] bg-[#030508] px-7 pb-[30px] pt-[52px]">
      <div className="mx-auto grid max-w-[1100px] grid-cols-1 gap-10 sm:grid-cols-2 lg:grid-cols-[2fr_1fr_1fr_1fr]">
        {/* footer-brand */}
        <div>
          <div className="mb-2.5 flex items-center gap-2.5">
            <span className="flex h-6 w-6 items-center justify-center rounded-[5px] bg-[linear-gradient(140deg,#4fc87a,#2da856)] text-[#06080e]">
              <Layers className="h-3 w-3" strokeWidth={2.3} />
            </span>
            <span className="text-[15px] font-bold tracking-[-0.01em] text-foreground">
              HospiceLink <span className="text-azure">CRM</span>
            </span>
          </div>
          <p className="my-2.5 mb-3.5 text-[13px] leading-[1.68] text-faint">
            We Market Plus builds purpose-built CRM platforms for healthcare and
            senior living operators. HospiceLink for hospice. CommunityLink for
            senior living.
          </p>
          <small className="text-[12px] text-white/[0.15]">
            © 2026 We Market Plus LLC. All rights reserved.
          </small>
        </div>

        {COLUMNS.map((col) => (
          <div key={col.heading}>
            <h6 className="mb-3.5 text-[10px] font-bold uppercase tracking-[0.1em] text-faint">
              {col.heading}
            </h6>
            <div className="space-y-[9px]">
              {col.links.map((link) => (
                <FooterAnchor key={link.label + link.to} link={link} />
              ))}
            </div>
          </div>
        ))}
      </div>

      <div className="mx-auto mt-7 flex max-w-[1100px] flex-wrap justify-between gap-2 border-t border-white/[0.08] pt-[22px] text-[12px] text-faint">
        <span>© 2026 We Market Plus LLC — Dallas, TX</span>
        <span>HIPAA-Ready · BAA Included · TLS 1.3 Encrypted</span>
      </div>
    </footer>
  );
}

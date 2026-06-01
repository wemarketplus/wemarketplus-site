import { Link } from 'react-router-dom';
import { BrandLogo } from './BrandLogo';

export function MarketingFooter() {
  const year = new Date().getFullYear();
  return (
    <footer className="border-t border-white/[0.06] bg-ink">
      <div className="mx-auto grid max-w-7xl grid-cols-2 gap-8 px-6 py-12 sm:grid-cols-4">
        <div className="col-span-2">
          <BrandLogo size="sm" />
          <p className="mt-3 max-w-xs text-sm text-muted">
            We Market Plus builds purpose-built CRM platforms for healthcare and
            senior living operators. HospiceLink for hospice. CommunityLink for
            senior living.
          </p>
          <a
            href="mailto:info@wemarketplus.com"
            className="mt-3 inline-block text-xs uppercase tracking-[0.1em] text-muted-soft hover:text-foreground"
          >
            info@wemarketplus.com
          </a>
        </div>
        <div className="space-y-2 text-sm">
          <p className="text-[11px] uppercase tracking-[0.14em] text-muted-soft">
            Product
          </p>
          <Link className="block text-muted hover:text-foreground" to="/pricing">
            HospiceLink
          </Link>
          <Link
            className="block text-muted hover:text-foreground"
            to="/communitylink"
          >
            CommunityLink
          </Link>
          <Link
            className="block text-muted hover:text-foreground"
            to="/demo/hospicelink/pro"
          >
            Live demo
          </Link>
        </div>
        <div className="space-y-2 text-sm">
          <p className="text-[11px] uppercase tracking-[0.14em] text-muted-soft">
            Legal
          </p>
          <Link className="block text-muted hover:text-foreground" to="/privacy">
            Privacy
          </Link>
          <Link className="block text-muted hover:text-foreground" to="/terms">
            Terms
          </Link>
          <Link
            className="block text-muted hover:text-foreground"
            to="/compliance"
          >
            Compliance
          </Link>
          <Link
            className="block text-muted hover:text-foreground"
            to="/sign-baa"
          >
            Sign BAA
          </Link>
        </div>
      </div>
      <div className="border-t border-white/[0.06] py-4">
        <p className="mx-auto max-w-7xl px-6 text-[11px] uppercase tracking-[0.12em] text-muted-soft">
          © {year} WeMarketPlus, Inc.
        </p>
      </div>
    </footer>
  );
}

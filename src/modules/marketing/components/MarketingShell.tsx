import { useEffect, type ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { MarketingHeader } from './MarketingHeader';
import { MarketingFooter } from './MarketingFooter';
import { AlertBar } from './AlertBar';
import { ActivityTicker } from './ActivityTicker';
import { ProductCards } from './ProductCards';

// Scroll to the `#section` in the URL after client-side navigation — the live
// site is a single page with in-page anchors, so /#pricing etc. must scroll.
function useHashScroll() {
  const { hash, pathname } = useLocation();
  useEffect(() => {
    if (!hash) return;
    const id = decodeURIComponent(hash.slice(1));
    const t = window.setTimeout(() => {
      document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
    }, 60);
    return () => window.clearTimeout(t);
  }, [hash, pathname]);
}

// Wraps every marketing page so header + footer stay consistent without
// each page re-importing them.
export function MarketingShell({ children }: { children: ReactNode }) {
  useHashScroll();
  return (
    <div className="marketing-root flex min-h-screen flex-col bg-bg">
      <MarketingHeader />
      <AlertBar />
      <ActivityTicker />
      <ProductCards />
      <main className="flex-1">{children}</main>
      <MarketingFooter />
    </div>
  );
}

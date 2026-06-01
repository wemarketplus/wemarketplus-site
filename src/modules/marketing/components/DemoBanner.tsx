import { Link } from 'react-router-dom';
import { Sparkles, X } from 'lucide-react';
import {
  PRODUCT_LABELS,
  TIER_LABELS,
  type Product,
  type Tier,
} from '@/shared/types';

interface DemoBannerProps {
  product: Product;
  tier: Tier;
}

// Sticky strip at the top of /demo/:product/:tier — mirrors the site's
// "DEMO MODE — No Login Required" callout. Pinned above the dashboard chrome.
export function DemoBanner({ product, tier }: DemoBannerProps) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-primary/40 bg-primary/15 px-6 py-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-primary">
      <div className="flex items-center gap-2">
        <Sparkles className="h-3.5 w-3.5" />
        Demo mode · {PRODUCT_LABELS[product]} {TIER_LABELS[tier]} · no login required
      </div>
      <Link
        to="/"
        aria-label="Exit demo"
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        Exit <X className="h-3 w-3" />
      </Link>
    </div>
  );
}

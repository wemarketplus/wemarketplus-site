import { ArrowRight } from 'lucide-react';
import type { ComponentType, ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent } from '@/shared/ui/core';

interface ClPortfolioCardProps {
  title: string;
  icon: ComponentType<{ className?: string }>;
  /** The headline figure. */
  value: string;
  /** One line saying what the figure means. */
  detail: ReactNode;
  /** Named exactly as the guide names the button ("Ledger", "View", "Full Pipeline"). */
  actionLabel: string;
  /**
   * Where the button goes, or null when the tenant's plan does not include the
   * destination. A null `to` renders the figure with an upgrade note instead of a
   * dead link — the guide is explicit that the deep financial screens are "on
   * larger plans", so a Gold owner should see the summary and be told why the
   * button is absent, not click through to a redirect.
   */
  to: string | null;
}

/**
 * One card on the Owner/Investor Portfolio Dashboard.
 *
 * The guide describes this screen entirely in terms of cards with named buttons
 * — "Click the Ledger button on the Financial Overview card", "Click View on the
 * Revenue Leakage card", "Click Full Pipeline from the Referral Pipeline card" —
 * so the card + named action is the unit of the layout rather than a bare tile.
 */
export function ClPortfolioCard({
  title,
  icon: Icon,
  value,
  detail,
  actionLabel,
  to,
}: ClPortfolioCardProps) {
  return (
    <Card>
      <CardContent className="px-5 py-5">
        <div className="flex items-start justify-between gap-3">
          <p className="text-[10.5px] font-semibold uppercase leading-[1.35] tracking-[0.12em] text-muted-soft">
            {title}
          </p>
          <span className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-[9px] bg-primary/[0.08] text-primary">
            <Icon className="h-4 w-4" />
          </span>
        </div>

        <p className="mt-4 text-[32px] font-bold leading-none tracking-[-0.02em] text-foreground">
          {value}
        </p>
        <p className="mt-2 text-[12.5px] text-muted">{detail}</p>

        {to ? (
          <Link
            to={to}
            className="mt-4 inline-flex items-center gap-1.5 rounded-pill border border-border/[0.12] px-3.5 py-1.5 text-[12px] font-bold text-foreground transition-colors hover:border-primary/40 hover:text-primary"
          >
            {actionLabel}
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        ) : (
          <p className="mt-4 text-[11px] uppercase tracking-[0.1em] text-muted-soft">
            {actionLabel} — available on Max
          </p>
        )}
      </CardContent>
    </Card>
  );
}

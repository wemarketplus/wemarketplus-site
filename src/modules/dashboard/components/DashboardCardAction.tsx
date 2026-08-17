import { Link } from 'react-router-dom';

/**
 * The pill-shaped link that sits in a dashboard card's header — "View all",
 * "Ledger", "Full Pipeline".
 *
 * Extracted because the Portfolio Dashboard adds four more cards with the same
 * affordance, and the styling was previously a 180-character class string written
 * out inline in `UnitStatusCard`. Five copies of it would drift the first time
 * anyone adjusted the border or the type scale.
 *
 * `aria-label` is required rather than optional. Every one of these links is
 * labelled with a generic verb — four cards on one screen whose only accessible
 * name is "View" is unusable with a screen reader's link list, so each caller must
 * say what it views.
 */
export function DashboardCardAction({
  to,
  label,
  ariaLabel,
}: {
  to: string;
  label: string;
  ariaLabel: string;
}) {
  return (
    <Link
      to={to}
      aria-label={ariaLabel}
      className="rounded-pill border border-border/[0.14] bg-surface-raised px-3 py-1.5 text-[11.5px] font-semibold text-foreground transition-colors hover:border-border/30"
    >
      {label}
    </Link>
  );
}

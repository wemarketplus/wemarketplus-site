import { Phone } from 'lucide-react';
import { Link } from 'react-router-dom';

// index.html .alert-bar — amber-tinted gradient strip: breathing amber dot,
// amber "Founders Pricing" lead, an azure "Lock in your rate" anchor, and a
// sage "Call us now" tel link.
export function AlertBar() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-2 border-b border-amber/[0.22] bg-[linear-gradient(90deg,rgba(201,144,58,0.08),rgba(201,144,58,0.04))] px-7 py-2.5 text-center text-[13px] font-medium text-muted">
      <span
        className="inline-block h-1.5 w-1.5 shrink-0 animate-breathe rounded-full bg-amber"
        aria-hidden="true"
      />
      <span className="whitespace-nowrap">
        <strong className="font-bold text-amber">Founders Pricing</strong> —
        Rates increase June 1, 2026. Every day you wait costs $200+/year.
      </span>
      <Link
        to="/#pricing"
        className="whitespace-nowrap border-b border-azure/[0.22] pb-px font-semibold text-azure transition-colors hover:text-foreground"
      >
        Lock in your rate →
      </Link>
      <span className="select-none text-faint" aria-hidden="true">
        |
      </span>
      <a
        href="tel:+19725550100"
        className="inline-flex items-center gap-1 whitespace-nowrap font-semibold text-sage transition-colors hover:text-foreground"
      >
        <Phone className="h-3.5 w-3.5" aria-hidden="true" />
        Call us now
      </a>
    </div>
  );
}

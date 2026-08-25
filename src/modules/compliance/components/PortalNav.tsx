import { NavLink } from 'react-router-dom';
import { GROUPS, PORTAL_NAV } from '../constants/portalContent';
import { cn } from '@/shared/utils/cn';

// Sub-nav for the Compliance Portal — mirrors the grouped left rail in the
// source (Assessment / Operations / Evidence / Security).
export function PortalNav() {
  return (
    <nav className="flex flex-wrap gap-x-6 gap-y-3 border-b border-border/[0.06] pb-4">
      {GROUPS.map((group) => (
        <div key={group} className="space-y-1.5">
          <p className="text-[9px] font-black uppercase tracking-label text-muted-soft">
            {group}
          </p>
          <div className="flex flex-wrap gap-1.5">
            {PORTAL_NAV.filter((i) => i.group === group).map((i) => (
              <NavLink
                key={i.to}
                to={i.to}
                className={({ isActive }) =>
                  cn(
                    'rounded-pill border px-3 py-1.5 text-[11px] font-semibold transition-colors',
                    isActive
                      ? 'border-azure/40 bg-azure/15 text-azure'
                      : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
                  )
                }
              >
                {i.label}
              </NavLink>
            ))}
          </div>
        </div>
      ))}
    </nav>
  );
}

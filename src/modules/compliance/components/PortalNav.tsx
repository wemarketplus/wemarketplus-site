import { NavLink } from 'react-router-dom';
import { PORTAL_NAV, type PortalNavItem } from '../constants/portalContent';
import { cn } from '@/shared/utils/cn';

const GROUPS: ReadonlyArray<PortalNavItem['group']> = [
  'Assessment',
  'Operations',
  'Evidence',
  'Security',
];

// Sub-nav for the Compliance Portal — mirrors the grouped left rail in the
// source (Assessment / Operations / Evidence / Security).
export function PortalNav() {
  return (
    <nav className="flex flex-wrap gap-x-6 gap-y-3 border-b border-white/[0.06] pb-4">
      {GROUPS.map((group) => (
        <div key={group} className="space-y-1.5">
          <p className="text-[9px] font-black uppercase tracking-[0.12em] text-[#334d6e]">
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
                      : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
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

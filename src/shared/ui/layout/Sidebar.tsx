import { NavLink } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';
import {
  SECTIONS_BY_PRODUCT,
  isNavItemVisible,
} from '@/shared/config/navigationConfig';
import { useRole, ROLE_LABELS } from '@/shared/rbac';
import {
  Product,
  Tier,
  TIER_LABELS,
  PRODUCT_LABELS,
  normalizeTier,
} from '@/shared/types';
import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site `.sb` exactly: 220px column, #071120 bg (HL) /
// #060f1c (CL), .sb-top brand block, .nav-sec section eyebrows (#334d6e, 9px,
// .12em caps), .nav-btn (#d0d8e8, 12px, 8/10px pad, 8px radius), active =
// solid tier color with #081426 text, admin items purple. .sb-foot at bottom.
export function Sidebar() {
  const { role } = useRole();
  const product = useAppSelector((s) => s.auth.user?.product) ?? Product.HospiceLink;
  const tier =
    normalizeTier(useAppSelector((s) => s.auth.user?.tier)) ?? Tier.Pro;

  const sections = SECTIONS_BY_PRODUCT[product];
  const isCommunity = product === Product.CommunityLink;

  // Active nav background per tier (matches .active-b / .active-g; Max uses
  // the lime btn color). CommunityLink uses amber.
  const activeBg = isCommunity
    ? 'bg-amber'
    : tier === Tier.Gold
    ? 'bg-gold'
    : tier === Tier.Max
    ? 'bg-lime'
    : 'bg-azure';

  return (
    <aside
      data-product={product}
      className={cn(
        'hidden h-full w-[220px] min-w-[220px] shrink-0 flex-col border-r border-white/[0.08] md:flex',
        isCommunity ? 'bg-[#060f1c]' : 'bg-[#071120]',
      )}
    >
      {/* .sb-top */}
      <div className="flex-shrink-0 px-3 pb-2 pt-3.5">
        <div className="text-[16px] font-black leading-tight text-azure">
          {isCommunity ? 'Community' : 'Hospice'}
          <span className={isCommunity ? 'text-amber' : 'text-gold'}>Link</span>
        </div>
        <div className="mt-0.5 text-[11px] text-[#8b949e]">
          {PRODUCT_LABELS[product]} · {TIER_LABELS[tier]}
        </div>
      </div>

      {/* .sb-nav */}
      <nav className="flex-1 overflow-y-auto px-2 pb-2" aria-label="Primary navigation">
        {sections.map((section) => {
          const visibleItems = section.items.filter((i) =>
            isNavItemVisible(i, role, tier),
          );
          if (visibleItems.length === 0) return null;
          const isAdmin = section.id.endsWith('intelligence') || section.id === 'admin' || section.id.endsWith('compliance');
          return (
            <div key={section.id}>
              {/* .nav-sec */}
              <span className="block px-1.5 pb-[3px] pt-2.5 text-[9px] font-black uppercase tracking-[0.12em] text-[#334d6e]">
                {section.label}
              </span>
              {visibleItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) =>
                    cn(
                      'mb-px block truncate rounded-[8px] px-2.5 py-2 text-[12px] font-semibold transition-colors',
                      isActive
                        ? cn(activeBg, 'text-[#081426]')
                        : isAdmin
                        ? 'text-[#c9aeff] hover:bg-[#6d28d9]/15'
                        : 'text-[#d0d8e8] hover:bg-white/[0.07] hover:text-white',
                    )
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          );
        })}
      </nav>

      {/* .sb-foot */}
      <div className="flex-shrink-0 border-t border-white/[0.07] px-3 py-2.5 text-[10px] uppercase tracking-[0.1em] text-[#8b949e]">
        {role ? (
          <>Signed in as <span className="font-bold text-foreground">{ROLE_LABELS[role]}</span></>
        ) : (
          'Not signed in'
        )}
      </div>
    </aside>
  );
}

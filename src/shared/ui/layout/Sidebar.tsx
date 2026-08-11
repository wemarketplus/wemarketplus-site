import { NavLink } from 'react-router-dom';
// Lucide is the icon system the reference design draws from (24px grid, 2px
// stroke, rounded caps) and is already the app's icon dependency — every
// NavItem in navigationConfig already carries one.
import { HeartPulse as BrandMark } from 'lucide-react';
import {
  // RoleSwitcher — the "Viewing as" control is switched off (see below).
  // RoleSwitcher,
  useActiveEntitlement,
} from '@/modules/access';
import {
  SECTIONS_BY_PRODUCT,
  isNavItemVisible,
} from '@/shared/config/navigationConfig';
import { useAppSelector } from '@/app/hooks';
import { useRole, roleTitle } from '@/shared/rbac';
import { Product, TIER_LABELS, PRODUCT_LABELS } from '@/shared/types';
import { cn } from '@/shared/utils/cn';

// 220px rail on the light surface wash: .sb-top brand block (mark + wordmark),
// .nav-sec section eyebrows, icon+label nav rows at an 8px radius, and .sb-foot
// at the bottom. Colour is token-driven and uniform — one accent for every
// product and tier, per the reference design.
export function Sidebar() {
  const { role } = useRole();
  // Product/tier follow the ACTIVE dashboard (which the switcher can change),
  // not the tenant's primary product — so a dual-product user viewing
  // CommunityLink sees the CommunityLink nav gated by their CommunityLink tier.
  const {
    product,
    tier,
    subscriptionStatus,
  } = useActiveEntitlement();
  // Live plan? Used only to decide whether to print the tier in the header
  // label — an unpaid ('incomplete') tenant shouldn't read as "· Pro". The tier
  // itself still drives nav colors/visibility below.
  const hasActivePlan = ['active', 'trialing', 'past_due'].includes(
    subscriptionStatus ?? '',
  );

  /**
   * A custom role's chosen tabs, when this user holds one. Ships on the auth payload
   * (see AuthService.withTenantPlanInfo), so the sidebar needs no extra request and
   * an ordinary user never has to be able to read the tenant's whole role design.
   *
   * A DISABLED custom role is ignored on purpose: the user falls back to their base
   * role's normal menu rather than being left with a role that no longer applies.
   */
  const customRole = useAppSelector((s) => s.auth.user?.customRole);
  const allowedNavKeys =
    customRole?.isActive && customRole.navKeys.length > 0
      ? customRole.navKeys
      : undefined;

  const sections = SECTIONS_BY_PRODUCT[product];
  const isCommunity = product === Product.CommunityLink;

  // ONE active accent for every product and tier — a tinted pill with
  // accent-coloured text. The rail previously shifted hue per tier/product
  // (gold / lime / azure / amber), which made the same screen look like four
  // different products; the design specifies a single quiet accent.

  return (
    <aside
      data-product={product}
      className="hidden h-full w-[220px] min-w-[220px] shrink-0 flex-col border-r border-border/[0.08] bg-surface-raised md:flex"
    >
      {/* .sb-top — brand block: a filled mark in a rounded square beside the
          wordmark, per the reference design. */}
      <div className="flex-shrink-0 px-3 pb-2 pt-3.5">
        <div className="flex items-center gap-2.5">
          <div
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] bg-primary"
          >
            <BrandMark className="h-[18px] w-[18px] text-primary-foreground" />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[15px] font-black leading-tight tracking-[-0.01em] text-foreground">
              {isCommunity ? 'Community' : 'Hospice'}
              <span className="text-primary">Link</span>
            </div>
            <div className="mt-0.5 truncate text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-soft">
              {PRODUCT_LABELS[product]}
              {hasActivePlan && ` · ${TIER_LABELS[tier]}`}
            </div>
          </div>
        </div>
        {/* "Viewing as" role preview — DISABLED. It only ever rendered for a
            HospiceLink management user, and the HospiceLink dashboards are not to
            show a role-preview section at all. The component and its store
            plumbing are left in place; restore by uncommenting this and the
            import above (and the preview resolution in usePermission). */}
        {/* <RoleSwitcher /> */}
      </div>

      {/* .sb-nav */}
      <nav className="flex-1 overflow-y-auto px-2 pb-2" aria-label="Primary navigation">
        {sections.map((section) => {
          const visibleItems = section.items.filter((i) =>
            isNavItemVisible(i, product, role, tier, allowedNavKeys, section.id),
          );
          if (visibleItems.length === 0) return null;
          const isAdmin = section.id.endsWith('intelligence') || section.id === 'admin' || section.id.endsWith('compliance');
          return (
            <div key={section.id}>
              {/* .nav-sec */}
              <span className="block px-1.5 pb-[3px] pt-2.5 text-[9px] font-black uppercase tracking-[0.12em] text-muted-soft">
                {section.label}
              </span>
              {visibleItems.map((item) => {
                const Icon = item.icon;
                /**
                 * Announced, not built. Rendered as an inert row rather than a
                 * NavLink: there is no route behind it, and a link that goes
                 * nowhere (or to a 404) is worse than no link. Not a <button>
                 * either — nothing happens on click, so it must not invite one.
                 * `aria-disabled` + the visible "Soon" badge say the same thing to
                 * a screen reader and to the eye.
                 */
                if (item.comingSoon) {
                  return (
                    <div
                      key={item.to}
                      aria-disabled="true"
                      className="mb-px flex cursor-default items-center gap-2.5 rounded-[8px] px-2.5 py-2 text-[12px] font-semibold text-muted-soft/70"
                    >
                      <Icon className="h-4 w-4 shrink-0 text-muted-soft/60" />
                      <span className="truncate">{item.label}</span>
                      <span className="ml-auto shrink-0 rounded-pill border border-border/[0.12] px-1.5 py-px text-[8px] font-black uppercase tracking-[0.1em] text-muted-soft">
                        Soon
                      </span>
                    </div>
                  );
                }
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.to === '/'}
                    className={({ isActive }) =>
                      cn(
                        'mb-px flex items-center gap-2.5 rounded-[8px] px-2.5 py-2 text-[12px] font-semibold transition-colors',
                        isActive
                          ? 'bg-primary/[0.09] text-primary'
                          : isAdmin
                          ? 'text-muted hover:bg-primary/[0.05] hover:text-primary'
                          : 'text-muted hover:bg-primary/[0.05] hover:text-foreground',
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <Icon
                          className={cn(
                            'h-4 w-4 shrink-0 transition-colors',
                            isActive ? '' : 'text-muted-soft',
                          )}
                        />
                        <span className="truncate">{item.label}</span>
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* .sb-foot */}
      <div className="flex-shrink-0 border-t border-border/[0.07] px-3 py-2.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
        {role ? (
          <>Signed in as <span className="font-bold text-foreground">{roleTitle(role, customRole?.name)}</span></>
        ) : (
          'Not signed in'
        )}
      </div>
    </aside>
  );
}

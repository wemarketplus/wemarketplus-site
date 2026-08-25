import { useMemo, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
// Lucide is the icon system the reference design draws from (24px grid, 2px
// stroke, rounded caps) and is already the app's icon dependency — every
// NavItem in navigationConfig already carries one.
import { HeartPulse as BrandMark } from 'lucide-react';
import { ViewingAsBadge, useActiveEntitlement } from '@/modules/access';
import {
  SECTIONS_BY_PRODUCT,
  isNavItemVisible,
} from '@/shared/config/navigationConfig';
import { useAppSelector } from '@/app/hooks';
import { SearchInput } from '@/shared/ui/core';
import { useRole, roleTitle } from '@/shared/rbac';
import { Product, TIER_LABELS, PRODUCT_LABELS } from '@/shared/types';
import { cn } from '@/shared/utils/cn';

// 200px rail on the light surface wash: .sb-top brand block (mark + wordmark),
// .nav-sec section eyebrows, icon+label nav rows at an 8px radius, and .sb-foot
// at the bottom. Colour is token-driven and uniform — one accent for every
// product and tier, per the reference design.
//
// SPACING SCALE — every nav row, in every section, on every dashboard, uses
// exactly these three constants. They exist so a row cannot be tuned per page:
// the rail is one component, and a one-off `py-` on a single item is what made
// the spacing read as uneven in the first place.
const NAV_ROW_BASE =
  'mb-0.5 flex h-8 items-center gap-2.5 rounded-sm px-2.5 text-[12px] font-semibold';
// Section eyebrows: same rhythm above every group, including the first.
const NAV_SECTION_HEADING =
  'block px-2.5 pb-1 pt-3 text-[10px] font-extrabold uppercase tracking-label text-muted';

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

  /**
   * MODULE SEARCH — filters THIS rail. Deliberately not the topbar's
   * Cmd/Ctrl+K palette (modules/search): that one answers "find a record"
   * (contacts, companies, prospects) and says so in its own empty state. This
   * one answers "where is that screen", over a rail that runs to ~40 rows
   * across eight sections at CommunityLink Max. Two different questions, so
   * reusing the palette would have meant teaching it a second vocabulary; the
   * shared <SearchInput> is the part worth reusing, and it is.
   */
  const [navQuery, setNavQuery] = useState('');
  const navigate = useNavigate();

  const allSections = SECTIONS_BY_PRODUCT[product];
  const isCommunity = product === Product.CommunityLink;

  /**
   * ONE notion of "visible" for the rail: entitlement/role visibility and the
   * text filter are applied in the same pass, so the empty-section check and
   * the "no modules match" state below cannot disagree with what is rendered.
   *
   * Matching the SECTION label too is what makes "financial" or "outreach"
   * work — the user's mental index of the rail is the eyebrows as much as the
   * rows.
   */
  const sections = useMemo(() => {
    const needle = navQuery.trim().toLowerCase();
    return allSections
      .map((section) => ({
        ...section,
        items: section.items.filter(
          (item) =>
            isNavItemVisible(item, product, role, tier, allowedNavKeys, section.id) &&
            (needle === '' ||
              item.label.toLowerCase().includes(needle) ||
              section.label.toLowerCase().includes(needle)),
        ),
      }))
      .filter((section) => section.items.length > 0);
  }, [allSections, navQuery, product, role, tier, allowedNavKeys]);

  /**
   * Enter goes to the first real match, so the keyboard path is type-and-go
   * rather than type-then-reach-for-the-mouse. `comingSoon` rows are skipped:
   * they have no route behind them (see the inert branch below), so navigating
   * to one would 404.
   */
  const firstMatch = navQuery.trim()
    ? sections.flatMap((section) => section.items).find((item) => !item.comingSoon)
    : undefined;

  // ONE active accent for every product and tier — a tinted pill with
  // accent-coloured text. The rail previously shifted hue per tier/product
  // (gold / lime / azure / amber), which made the same screen look like four
  // different products; the design specifies a single quiet accent.

  return (
    <aside
      data-product={product}
      className="hidden h-full w-[200px] min-w-[200px] shrink-0 flex-col border-r border-border/[0.08] bg-surface-raised md:flex"
    >
      {/* .sb-top — brand block: a filled mark in a rounded square beside the
          wordmark, per the reference design. */}
      <div className="flex-shrink-0 px-3 pb-2 pt-3.5">
        <div className="flex items-center gap-2.5">
          <div
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary"
          >
            <BrandMark className="h-[18px] w-[18px] text-primary-foreground" />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[15px] font-black leading-tight tracking-[-0.01em] text-foreground">
              {isCommunity ? 'Community' : 'Hospice'}
              <span className="text-primary">Link</span>
            </div>
            <div className="mt-0.5 truncate text-[10px] font-semibold uppercase tracking-label text-muted-soft">
              {PRODUCT_LABELS[product]}
              {hasActivePlan && ` · ${TIER_LABELS[tier]}`}
            </div>
          </div>
        </div>
        {/* "Viewing as" — reports the signed-in role, on both dashboards, for
            every role. The end-user guide makes it a step-1 instruction
            ("confirm you're set to Sales Marketer"), so it must be visible to
            everyone; it shows that one role and offers no others. */}
        <ViewingAsBadge />
      </div>

      {/* MODULE SEARCH — between the brand block and the rows, so it reads as a
          control over the list it filters rather than as one more nav row.
          Sized to the rail: `h-8` is NAV_ROW_BASE's own row height and 12px is
          the row label size, so the field sits in the same rhythm as the rows
          instead of the 44px/14px page-form geometry CONTROL_HEIGHT gives it.
          A plain filter input with `aria-controls`, NOT the combobox pattern in
          ListboxSelect: the results are the nav landmark itself, which stays in
          the DOM and keeps its own role. */}
      <div className="flex-shrink-0 px-2 pb-1">
        <SearchInput
          value={navQuery}
          onChange={setNavQuery}
          placeholder="Search menu…"
          aria-label="Search menu"
          aria-controls="sidebar-nav"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && firstMatch) {
              e.preventDefault();
              navigate(firstMatch.to);
              setNavQuery('');
            }
          }}
          className="h-8 text-[12px]"
        />
      </div>

      {/* .sb-nav */}
      <nav
        id="sidebar-nav"
        className="flex-1 overflow-y-auto px-2 pb-2"
        aria-label="Primary navigation"
      >
        {sections.map((section) => {
          // Already filtered by the memo above — both for visibility and for the
          // search needle — so a section reaching here always has rows.
          const visibleItems = section.items;
          const isAdmin = section.id.endsWith('intelligence') || section.id === 'admin' || section.id.endsWith('compliance');
          return (
            <div key={section.id}>
              {/* .nav-sec — MAIN / SALES & OUTREACH / FINANCIAL / ADMIN.
                  Reads as a heading through the token change (muted rather than
                  muted-soft, which failed contrast on the light rail) plus one
                  step up in size, NOT through extra weight: at 9px/900 the
                  glyphs were dense enough to blur together. Still visibly
                  quieter than a nav row — uppercase, tracked out, and a size
                  below the 12px item labels. */}
              <span className={NAV_SECTION_HEADING}>{section.label}</span>
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
                      className={cn(NAV_ROW_BASE, 'cursor-default text-muted-soft/70')}
                    >
                      <Icon className="h-4 w-4 shrink-0 text-muted-soft/60" />
                      <span className="truncate">{item.label}</span>
                      <span className="ml-auto shrink-0 rounded-pill border border-border/[0.12] px-1.5 py-px text-[8px] font-black uppercase tracking-label text-muted-soft">
                        Soon
                      </span>
                    </div>
                  );
                }
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    /**
                     * EXACT matching for every row, not just "/".
                     *
                     * Without `end`, NavLink treats the target as a path PREFIX, so
                     * any row that is an ancestor of another lights up alongside it:
                     * on /compliance/audit both "HIPAA audit log" and the /compliance
                     * row rendered as active at once. Two highlighted rows tell the
                     * user they are in two places.
                     *
                     * Safe to apply to all of them because the nav is flat — every
                     * item points at a leaf route, and record detail is shown in
                     * drawers rather than child routes, so there is no row that needs
                     * to stay lit for a deeper path.
                     */
                    end
                    /**
                     * ACTIVE STATE — three signals, not one.
                     *
                     * The previous active row was a 9% accent tint and accent
                     * text, which on the light rail is a wash a few percent off
                     * the sidebar's own background: with a hover tint sitting at
                     * 5%, "selected" and "the mouse is here" were nearly the same
                     * swatch. Depth of tint alone cannot carry this.
                     *
                     * So the active row now also gets an accent bar on its
                     * leading edge and a heavier weight. The bar is the signal
                     * that survives — it is the only element on the rail with
                     * that shape, so the eye finds the current page without
                     * comparing fills. Kept to the existing `primary` token at a
                     * restrained 14% fill rather than a saturated block, per the
                     * design's quiet-accent rule.
                     */
                    className={({ isActive }) =>
                      cn(
                        NAV_ROW_BASE,
                        'relative transition-colors',
                        isActive
                          ? 'bg-primary/[0.14] font-bold text-primary before:absolute before:left-0 before:top-1/2 before:h-[18px] before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-primary before:content-[""]'
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
        {/* Only reachable with a needle typed: with an empty query the rail
            always has rows. `text-muted`, not `muted-soft`, for the same
            contrast reason as the section eyebrows above. */}
        {sections.length === 0 && (
          <p className="px-2.5 pt-3 text-[11px] text-muted">No modules match.</p>
        )}
      </nav>

      {/* .sb-foot */}
      <div className="flex-shrink-0 border-t border-border/[0.07] px-3 py-2.5 text-[10px] uppercase tracking-label text-muted-soft">
        {role ? (
          <>Signed in as <span className="font-bold text-foreground">{roleTitle(role, customRole?.name)}</span></>
        ) : (
          'Not signed in'
        )}
      </div>
    </aside>
  );
}

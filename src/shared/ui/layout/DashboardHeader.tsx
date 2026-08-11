import { LogOut } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { ProductSwitcher } from '@/modules/access';
import { logout } from '@/modules/auth';
import { NotificationsBell } from '@/modules/notifications';
import { GlobalSearch } from '@/modules/search';
import { roleTitle } from '@/shared/rbac';
import { Button } from '@/shared/ui/core/Button';
import { useOverlayOpen } from '@/shared/ui/feedback';
import { cn } from '@/shared/utils/cn';

// Topbar mirrors wemarketplus-site dashboards: thin hairline divider, user
// identity + notifications on the right, no theme toggle (dark-only app).
//
// `relative z-30` is LOAD-BEARING, not styling. `backdrop-blur-sm` makes this
// header a stacking context, so a dropdown inside it (the product switcher, and
// anything else that opens downward from here) cannot escape above `<main>` on
// its own z-index alone — main comes later in DOM order and paints over the whole
// header subtree. The menu still LOOKED right, but `elementFromPoint` over it
// returned the page's <h1>, so every click on it hit the content underneath: the
// dashboard switcher appeared to do nothing at all. Positioning the header lifts
// the whole subtree above main. Kept at 30 so the fixed z-50 overlays
// (NotificationsDrawer, Modal) and the z-[100] command palette still cover it.

export function DashboardHeader() {
  const dispatch = useAppDispatch();
  const user = useAppSelector((s) => s.auth.user);
  // No topbar while a popup form is open. `invisible` rather than unmounting: the
  // 64px row stays, so the page behind the backdrop does not jump up 64px on open
  // and back down on close. visibility:hidden also takes the whole subtree out of
  // hit-testing, tab order, and the accessibility tree, so nothing in here can be
  // reached from behind the modal.
  //
  // The Cmd/Ctrl+K command palette deliberately does NOT set this flag: it is
  // rendered inside this header (via GlobalSearch), and visibility is inherited —
  // hiding the header would hide the palette with it.
  const overlayOpen = useOverlayOpen();

  const initials = user
    ? `${user.firstName?.[0] ?? ''}${user.lastName?.[0] ?? ''}`.toUpperCase() || '?'
    : '';

  return (
    <header
      className={cn(
        'relative z-30 flex h-16 items-center justify-between border-b border-border/[0.06] bg-bg/80 px-6 backdrop-blur-sm',
        overlayOpen && 'invisible',
      )}
    >
      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-soft">
        WeMarketPlus CRM
      </div>

      <div className="flex items-center gap-2">
        <GlobalSearch />
        {/* Which dashboard is live, next to the bell. Available to every
            authenticated user — both dashboards, any role. */}
        <ProductSwitcher />
        <NotificationsBell />
        {user && (
          <div className="flex items-center gap-3 rounded-pill border border-border/[0.08] bg-surface/60 py-1 pr-3 pl-1">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/20 text-[11px] font-semibold text-primary">
              {initials}
            </div>
            <div className="hidden text-right sm:block">
              <p className="text-xs font-semibold text-foreground leading-none">
                {user.firstName} {user.lastName}
              </p>
              <p className="mt-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft leading-none">
                {roleTitle(user.role, user.customRole?.name)}
              </p>
            </div>
          </div>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => dispatch(logout())}
          aria-label="Sign out"
        >
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Sign out</span>
        </Button>
      </div>
    </header>
  );
}

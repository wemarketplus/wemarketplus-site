import { LogOut } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { ProductSwitcher } from '@/modules/access';
import { logout } from '@/modules/auth';
import { NotificationsBell } from '@/modules/notifications';
import { GlobalSearch } from '@/modules/search';
import { roleTitle } from '@/shared/rbac';
import { Button } from '@/shared/ui/core/Button';
import { confirm, useOverlayOpen } from '@/shared/ui/feedback';
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

  /**
   * Sign-out ASKS FIRST. It used to dispatch `logout()` straight from the click,
   * so a mis-aimed click on a control that sits inches from the notifications
   * bell ended the session outright — and because the button is in the shell,
   * that is reachable from every screen in the app, including one with a
   * half-filled form open.
   *
   * Reuses the same `confirm()` host every delete in the app already goes
   * through, so there is no second dialog implementation to keep in sync.
   * `destructive: false` — signing out is reversible (log back in), so this
   * gets the neutral primary button and no "cannot be undone" line, unlike a
   * record delete.
   *
   * Fails closed: `confirm()` resolves false when no host is mounted, so a
   * missing ConfirmHost keeps the user signed in rather than logging them out.
   */
  const signOut = async () => {
    const ok = await confirm({
      title: 'Sign out?',
      body: 'You will be returned to the sign-in screen and any unsaved work on this page will be lost.',
      confirmLabel: 'Sign out',
      cancelLabel: 'Cancel',
      destructive: false,
    });
    if (ok) dispatch(logout());
  };

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

      {/*
        Every control in this row is 36px tall (h-9 — the Button `sm`/`icon`
        size), so they share one centre line and one cap height. They were
        previously each sized by their own padding (`py-1`, `py-1.5`, `h-9`),
        which left the search pill, the switcher, the bell and the profile chip
        at four different heights stacked against a hairline — the "unbalanced"
        header. The sizing now lives in each component (see GlobalSearch,
        ProductSwitcher, NotificationsBell), not in per-instance overrides here.

        `gap-2` throughout, widening to `gap-3` before the sign-out button so the
        session-ending control is not flush against the profile chip it is most
        likely to be mis-clicked for.
      */}
      <div className="flex items-center gap-2">
        <GlobalSearch />
        {/* Which dashboard is live, next to the bell. Available to every
            authenticated user — both dashboards, any role. */}
        <ProductSwitcher />
        <NotificationsBell />
        {user && (
          <div className="flex h-9 items-center gap-2.5 rounded-pill border border-border/[0.08] bg-surface/60 pl-1 pr-3">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[11px] font-semibold text-primary">
              {initials}
            </div>
            <div className="hidden leading-none sm:block">
              <p className="text-[12px] font-semibold leading-none text-foreground">
                {user.firstName} {user.lastName}
              </p>
              <p className="mt-1 text-[10px] uppercase leading-none tracking-[0.1em] text-muted-soft">
                {roleTitle(user.role, user.customRole?.name)}
              </p>
            </div>
          </div>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={signOut}
          aria-label="Sign out"
          className="ml-1"
        >
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Sign out</span>
        </Button>
      </div>
    </header>
  );
}

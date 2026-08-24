import { LogOut } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { persistor } from '@/app/store';
import { ProductSwitcher } from '@/modules/access';
import { logout, useLogoutMutation } from '@/modules/auth';
import { NotificationsBell } from '@/modules/notifications';
import { GlobalSearch } from '@/modules/search';
import { roleTitle } from '@/shared/rbac';
import { Button } from '@/shared/ui/core/Button';
import {
  HEADER_CONTROL_BASE,
  HEADER_CONTROL_HEIGHT,
} from '@/shared/ui/core/controlStyles';
import { OVERLINE } from '@/shared/ui/core/typography';
import {
  SHELL_GUTTER_X,
  SHELL_HEADER_HEIGHT,
  SHELL_HEADER_STICKY,
} from './shellStyles';
import { confirm, useOverlayOpen } from '@/shared/ui/feedback';
import { cn } from '@/shared/utils/cn';

// Topbar mirrors wemarketplus-site dashboards: thin hairline divider, user
// identity + notifications on the right, no theme toggle (dark-only app).
//
// RENDERED INSIDE THE SCROLL CONTAINER, as `<main>`'s first child, stuck to the
// top — not as a sibling above it. That is what makes its right edge line up
// with the page's: a scrolling `<main>` loses a scrollbar's width out of its
// content box, and a topbar outside that box cannot know how much. See
// SHELL_HEADER_STICKY in shellStyles.ts for the measurements and for why the
// `z-30` is still load-bearing after the move.
//
// The height and the horizontal gutter both come from shellStyles too: the
// gutter MUST equal the page wrapper's or the topbar's contents stop lining up
// with the page's, which is the whole point of the arrangement.

// Ceiling on how long sign-out waits for the server to acknowledge the
// revocation before giving up and clearing this device anyway.
const REVOKE_TIMEOUT_MS = 4000;

export function DashboardHeader() {
  const dispatch = useAppDispatch();
  const [revokeSession] = useLogoutMutation();
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
   *
   * On confirm it then has to actually END THE SESSION, which is three steps,
   * in this order for reasons each step documents below. Clearing the Redux
   * token — all this used to do — only makes the CLIENT forget: the refresh
   * token stayed valid server-side until natural expiry, so a captured one kept
   * minting access tokens for an account whose owner had signed out.
   */
  const signOut = async () => {
    const ok = await confirm({
      title: 'Sign out?',
      body: 'You will be returned to the sign-in screen and any unsaved work on this page will be lost.',
      confirmLabel: 'Sign out',
      cancelLabel: 'Cancel',
      destructive: false,
    });
    if (!ok) return;

    /**
     * 1. Revoke server-side FIRST, while the token still exists.
     *
     * `POST /auth/logout` is auth-required and `baseQuery` reads the bearer out
     * of `state.auth.token`, so clearing the store before this call would send
     * it unauthenticated and revoke nothing. It revokes every refresh token in
     * the family AND records a revocation instant that the backend's JWT
     * strategy checks `iat` against, which is what kills already-issued access
     * tokens too.
     *
     * Best-effort but BOUNDED: a user who clicked "Sign out" must end up signed
     * out of this device even with no network, so a failure or a hang cannot be
     * allowed to strand them on an authenticated screen. Whichever way this
     * settles, step 2 runs.
     */
    await Promise.race([
      revokeSession().unwrap().catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, REVOKE_TIMEOUT_MS)),
    ]);

    // 2. Forget the credentials locally.
    dispatch(logout());

    /**
     * 3. Flush, then hard-reload into /login.
     *
     * ProtectedRoute's <Navigate> already bounces an unauthenticated user, so
     * the reload is not what performs the redirect — it is what discards the
     * 54 RTK Query caches, which are keyed by endpoint+args with no notion of
     * WHO fetched them. Without it, signing out and signing in as someone else
     * in the same tab re-mounts those queries against still-warm entries (RTKQ
     * serves a cached entry to a new subscriber without refetching), so the
     * next user is shown the previous user's records for up to `keepUnusedDataFor`.
     * On patient data that is a disclosure, not a stale-UI annoyance.
     *
     * `flush()` is what makes the reload safe: redux-persist writes are
     * throttled, so reloading straight after the dispatch can race the write
     * and rehydrate the OLD authenticated state — signing the user back in.
     * This is the same "hard redirect so caches reset cleanly" path baseQuery's
     * 401 handler takes; the two now differ only in who triggered them.
     */
    await persistor.flush();
    window.location.href = '/login';
  };

  return (
    <header
      className={cn(
        'flex items-center justify-between border-b border-border/[0.06] bg-bg backdrop-blur-md',
        // `sticky top-0 z-30` — see SHELL_HEADER_STICKY.
        //
        // OPAQUE `bg-bg`, not the `/80` this carried as a non-sticky row. The
        // translucency used to cost nothing because nothing ever passed behind
        // it — the topbar sat ABOVE the scroll container. Now that page content
        // scrolls under it, a translucent bar ghosts that content through
        // itself: at `/80` a table row's "Independent Living" cell and its
        // status pill were plainly legible through "Search…" and the product
        // switcher, and at `/95` they were still faintly visible as smudges.
        // There is no opacity that both frosts and stays clean here, so the bar
        // is opaque.
        //
        // `backdrop-blur-md` is RETAINED on purpose even though an opaque
        // background makes it invisible: `backdrop-filter` is what makes this
        // element a containing block for fixed-position descendants, and
        // CommandPalette (rendered from in here) portals to document.body
        // precisely because of that. Dropping the blur would silently make that
        // portal look redundant — see the comment in CommandPalette.tsx for the
        // bug that reappears if someone then removes it.
        SHELL_HEADER_STICKY,
        SHELL_HEADER_HEIGHT,
        SHELL_GUTTER_X,
        overlayOpen && 'invisible',
      )}
    >
      {/* One eyebrow style for the whole app — 0.16em here against 0.08em on
          every other kicker was one of the fourteen trackings in use for this
          single role. See typography.ts (OVERLINE). */}
      <div className={OVERLINE}>WeMarketPlus CRM</div>

      {/*
        Every control in this row is 36px tall AND wears the same hairline and
        surface — both from HEADER_CONTROL_* in controlStyles.ts, which each
        control imports rather than restating.

        The heights were already equal; the borders were not, and that was the
        remaining half of the "unbalanced header" report. The search pill, the
        switcher and the profile chip each carried their own copy of
        `border-border/[0.08] bg-surface/60` while the bell and the sign-out
        button were `ghost` Buttons with no border at all — so the row read
        bordered, bordered, BARE, bordered, BARE, and the bell in particular
        looked like a glyph dropped between two chips rather than a peer of them.
      */}
      <div className="flex items-center gap-2">
        <GlobalSearch />
        {/* Which dashboard is live, next to the bell. Available to every
            authenticated user — both dashboards, any role. */}
        <ProductSwitcher />
        <NotificationsBell />
        {user && (
          <div
            className={cn(
              HEADER_CONTROL_BASE,
              HEADER_CONTROL_HEIGHT,
              'flex items-center gap-2.5 pl-1 pr-3',
            )}
          >
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[11px] font-semibold text-primary">
              {initials}
            </div>
            <div className="hidden leading-none sm:block">
              <p className="text-[12px] font-semibold leading-none text-foreground">
                {user.firstName} {user.lastName}
              </p>
              <p className="mt-1 text-[10px] uppercase leading-none tracking-label text-muted-soft">
                {roleTitle(user.role, user.customRole?.name)}
              </p>
            </div>
          </div>
        )}
        {/* `outline`, not `ghost`. As a ghost it was the one control in the row
            with no hit area of its own, which is what made the right end of the
            header look like it trailed off. It keeps the quiet 600 weight, so
            it still does not compete with a page's primary action. */}
        <Button
          variant="outline"
          size="sm"
          onClick={signOut}
          aria-label="Sign out"
          className="ml-1 border-border/[0.08] text-muted hover:text-foreground"
        >
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Sign out</span>
        </Button>
      </div>
    </header>
  );
}

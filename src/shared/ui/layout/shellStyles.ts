/**
 * The shell's ONE horizontal gutter, shared by the topbar and the page below it.
 *
 * ── The bug this fixes ────────────────────────────────────────────────────────
 * The header and the scrolling page were padded independently, so the topbar's
 * content rail never lined up with the page's. Measured in the running app at a
 * 1517px viewport:
 *
 *   DashboardLayout  main px-[22px]          → page rail  222 … 1495.8
 *   RootRoute        main px-6 sm:px-8       → page rail  232 … 1469.1
 *   DashboardHeader      px-6                → topbar rail 224 … 1493.8
 *
 * On a list page the "Sign out" button therefore sat 2px inside the content
 * edge; on the home dashboard it OVERHUNG the content by 24.7px, because that
 * screen also clamped itself to `max-w-7xl`. Nothing was misaligned by enough
 * to look like a bug on its own — it just read as a header whose contents were
 * not quite balanced against the page, which is exactly the report. Navigating
 * from `/` to `/leads` also slid the whole page 10px left while the topbar
 * stayed put.
 *
 * Pinning ONE constant that both the topbar and `<main>` import is what makes
 * it hold. Tuning the two numbers to match by hand is what produced the 2px in
 * the first place: they were `px-6` and `px-[22px]`, which any reader would
 * assume were meant to be the same value.
 *
 * 24px (`px-6`) rather than the old 22px: it is on Tailwind's own spacing scale,
 * so it can be reached without an arbitrary value and cannot drift to 21 or 23.
 */
export const SHELL_GUTTER_X = 'px-6';

/**
 * The SCROLL CONTAINER — `<main>` itself. It carries no horizontal padding of
 * its own, because the topbar now lives inside it (see SHELL_CONTENT_PADDING).
 *
 * `scrollbar-gutter: stable` reserves the scrollbar's width whether or not this
 * page is long enough to need one. Without it the content box is ~15px narrower
 * on a page that scrolls than on one that does not (on any platform with classic
 * scrollbars — Windows, most Linux), so moving between a short screen and a long
 * one shifted the whole page sideways and changed every column width with it.
 * That is the same class of complaint as the gutter mismatch above, just driven
 * by content length instead of by which shell the route happened to use.
 *
 * Because the topbar is inside this element, the reserved gutter is subtracted
 * from the topbar too — which is what finally makes its right edge agree with
 * the page's. See SHELL_HEADER_STICKY.
 */
export const SHELL_MAIN_SCROLL = '[scrollbar-gutter:stable]';

/**
 * The page's own padding, on the wrapper INSIDE the scroll container that holds
 * the routed content — not on `<main>`, so the sticky topbar above it can sit
 * flush against the top of the scroll box while still sharing the same
 * horizontal gutter.
 */
export const SHELL_CONTENT_PADDING = `${SHELL_GUTTER_X} pb-[60px] pt-[18px]`;

/**
 * The topbar sits INSIDE the scroll container, as its first child, stuck to the
 * top.
 *
 * ── Why it moved ─────────────────────────────────────────────────────────────
 * As a SIBLING of `<main>` it could never line up with the page on the right.
 * Equalising the two gutters (24px each) fixed the LEFT edge exactly, but a
 * scrolling `<main>` also loses a scrollbar's width out of its content box —
 * and the topbar, being outside that box, did not. Measured at a 1517px
 * viewport: page content ended at 1477, "Sign out" at 1493.8. Every attempt to
 * close that from the outside is a guess at a number only the platform knows
 * (~15px on classic scrollbars, 0 on macOS's overlay ones), so it cannot be
 * done with padding.
 *
 * Inside the scroll container the question disappears: the topbar and the
 * content wrapper are both block children of the same box, so they are the same
 * width by construction, on every platform, whether or not the page scrolls.
 *
 * ── What this does to the stacking context ───────────────────────────────────
 * `z-30` is still LOAD-BEARING, for a reason that has now changed. It used to
 * be there because `<main>` came LATER IN DOM ORDER and painted over the whole
 * header subtree: the product-switcher menu looked right but `elementFromPoint`
 * over it returned the page's <h1>, so every click on it hit the content
 * underneath and the switcher appeared to do nothing. That specific ordering
 * problem is gone — the topbar is now the FIRST child, and the content wrapper
 * that follows it is unpositioned, so the positioned topbar paints above it.
 * The z-index is kept anyway because `sticky` + `z-30` is what guarantees that
 * ordering against any positioned element a page may introduce, and 30 still
 * leaves the fixed z-50 overlays (NotificationsDrawer, Modal) and the z-[100]
 * command palette above it.
 *
 * Two things make this safe rather than a new clipping bug:
 *   · CommandPalette already portals to document.body — it had to, because this
 *     header's `backdrop-blur` establishes a containing block for fixed-position
 *     children. So the one fixed overlay rendered from in here never depended on
 *     the header's position in the tree.
 *   · The product-switcher menu is a plain `absolute` child that opens DOWNWARD
 *     and is `right-0` within the header, so it stays inside the scroll
 *     container's bounds and is not clipped by `overflow-y: auto`.
 */
export const SHELL_HEADER_STICKY = 'sticky top-0 z-30';

/**
 * Topbar height. `h-16` is restated here rather than inline in DashboardHeader
 * so the three shells cannot disagree about how tall the row is.
 */
export const SHELL_HEADER_HEIGHT = 'h-16';

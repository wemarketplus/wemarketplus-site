/**
 * The type scale — ONE size, weight, colour and tracking per role.
 *
 * ── The bug this fixes ────────────────────────────────────────────────────────
 * The app had colour tokens (index.css) and control geometry (controlStyles.ts)
 * but NO typography system, so every screen picked its own numbers. Measured
 * across `src/modules` + `src/shared`: 28 distinct font sizes, 8 font weights
 * and 14 letter-spacings, with `text-sm`/`text-[14px]` and `text-xs`/
 * `text-[12px]` both in use for the SAME size — the same style spelled two ways,
 * which is how a scale silently doubles.
 *
 * The page title was the visible symptom. 48 files copy-pasted
 * `font-display text-3xl text-foreground`, but the home dashboard shipped
 * `text-4xl leading-none` (36px) and five other pages shipped `text-xl`/
 * `text-lg` (20px/18px) — so "the page's name" ranged from 18px to 36px
 * depending on which screen you were on. That is the "some headings appear
 * excessively large and bold, while similar headings on other screens are
 * smaller" report, exactly.
 *
 * Section headings were worse because the drift was INSIDE shared components:
 * <SectionHeader> was an h2 at 22px/900, <CardTitle> an h3 at 18px/800, and 34
 * hand-rolled h2s split evenly between `text-sm font-semibold` and
 * `text-base font-semibold`. Four competing answers to "what does a section
 * heading look like", two of them shipped from `shared/ui`.
 *
 * ── Why class strings and not just Tailwind utilities ─────────────────────────
 * A scale only holds if there is one NAME per role that call sites reach for
 * instead of re-deriving the numbers. `TITLE` is a decision; `text-3xl` is a
 * measurement, and a measurement invites the next author to pick a different
 * one. Sizes stay as Tailwind utilities inside these constants so the values
 * remain greppable and the Tailwind JIT still sees them.
 *
 * Every constant carries its own COLOUR, because the report names colour drift
 * too ("similar headings ... use different font colors"). Callers append layout
 * (margins, truncation, flex) via `cn()`; they should not be re-stating size,
 * weight, tracking or colour.
 */

/** Marketing-only hero. Not for app chrome — see PAGE_TITLE. */
export const DISPLAY_TITLE = 'font-display text-4xl leading-tight text-foreground';

/**
 * The name of the screen you are on — one per page, rendered as <h1>.
 *
 * 30px/700. `font-display` (index.css) pins the family, -0.5px tracking and
 * weight 800; `font-bold` overrides that last one back to 700, and wins because
 * `.font-display` lives in `@layer base` while Tailwind's weight utilities are
 * in `@layer utilities`.
 *
 * WHY 700 AND NOT THE FAMILY'S 800. 800 is a display weight. At 30px across the
 * full width of a page header it renders heavier than anything else on screen,
 * which is the "heading appears excessively bold" report — filed against the Lead
 * pipeline title, but true of all 110 page titles, since they all resolve here.
 * The same complaint was already answered the same way for the filled buttons
 * (Button.tsx: 800 → 700), so 700 is now the app's top weight throughout: this
 * title at 30px, SECTION_TITLE at 16px. The heading still dominates by SIZE —
 * nearly double the section heading — which is the axis that should carry it.
 *
 * DISPLAY_TITLE keeps 800: a marketing hero is the one place a display weight is
 * the point.
 */
export const PAGE_TITLE = 'font-display text-3xl font-bold text-foreground';

/** The line under a PAGE_TITLE. */
export const PAGE_SUBTITLE = 'text-sm text-muted';

/**
 * A titled block inside a page — a card header, a panel header, a
 * <SectionHeader> — as <h2>.
 *
 * 16px/700 is the MAJORITY value promoted to a token, not a new number. The same
 * role was being written four ways: 18px/800 (<CardTitle>, 1 call site),
 * 22px/900 (<SectionHeader>, 18 call sites), 16px/600 (18 hand-rolled) and
 * 14px/600 (17 hand-rolled). The split fell along module lines rather than along
 * anything a user could see — a card title in Settings and Billing was 16px, the
 * identical card title on the CommunityLink dashboard and the Intelligence pages
 * was 14px — which is the "similar headings on other screens are smaller" report
 * precisely.
 *
 * 16px is where 18 of the 35 hand-rolled ones already were; 700 is one step up
 * from their 600 so a heading reads as a heading and not as bold body copy.
 * Deliberately NOT 22px/900: against the 30px/800 PAGE_TITLE it always sits
 * beneath, that was near enough to compete with the name of the screen, which is
 * the "excessively large and bold" half of the same report.
 */
export const SECTION_TITLE = 'text-[16px] font-bold leading-tight text-foreground';

/** The line under a SECTION_TITLE. */
export const SECTION_SUBTITLE = 'text-[13px] leading-relaxed text-muted';

/**
 * A sub-block inside a section — the smallest real heading, as <h3>/<h4>.
 * A clear step below SECTION_TITLE rather than a near-miss of it.
 */
export const SUBSECTION_TITLE = 'text-sm font-bold leading-tight text-foreground';

/** Default body copy. */
export const BODY = 'text-sm text-foreground';

/** Secondary body copy — help text, descriptions, empty-state prose. */
export const BODY_MUTED = 'text-sm text-muted';

/**
 * The uppercase eyebrow/kicker above a title and the column headers in tables.
 * Tracking is the one value it can be, not one of the 14 that were in use
 * (0.02em … 0.16em) for the same visual role.
 */
export const OVERLINE = 'text-[11px] font-semibold uppercase tracking-label text-muted-soft';

/** Form-field label. Matches <Label>. */
export const FIELD_LABEL = 'text-[12px] font-semibold text-foreground';

/** Timestamps, counts, footnotes — the smallest text that is still prose. */
export const CAPTION = 'text-[12px] text-muted';

/**
 * Below CAPTION. Reserved for badge text and metadata that is deliberately
 * quiet; 10px is the floor, so nothing in the app should go under it.
 */
export const MICRO = 'text-[10px] text-muted-soft';

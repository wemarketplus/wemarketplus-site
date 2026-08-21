interface EntityPaginationProps {
  page: number;
  lastPage: number;
  // True while a background refetch is in flight (shows a subtle hint).
  isFetching?: boolean;
  onPrev: () => void;
  onNext: () => void;
}

// Page N of M + Previous/Next controls. Lifted verbatim from the users page so
// every entity list paginates identically.
export function EntityPagination({
  page,
  lastPage,
  isFetching,
  onPrev,
  onNext,
}: EntityPaginationProps) {
  /**
   * DISABLED is communicated by colour and cursor, not by fading the control
   * out of existence.
   *
   * `disabled:opacity-40` was applied to a button whose text was ALREADY the
   * muted token — the two compounded to roughly 1.7:1 against the page, so on
   * page 1 the "Previous" button was not so much unavailable as invisible, and
   * the footer looked like it had lost a control. Opacity is the wrong tool
   * here: it dims the border and the label by the same factor, so nothing is
   * left to hold the shape.
   *
   * Instead the disabled state keeps a full-strength (if lighter-toned) border
   * and `text-muted-soft`, which stays legible, and drops the hover affordances
   * plus `cursor-not-allowed`. Enabled and disabled remain easy to tell apart
   * because the enabled button is a full-contrast `text-foreground` on hover and
   * `text-muted` at rest — a difference in hue and interactivity rather than one
   * of "present" versus "faded away".
   */
  const btn =
    'rounded-pill border px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors ' +
    'border-border/[0.14] text-muted hover:border-border/30 hover:bg-foreground/[0.04] hover:text-foreground ' +
    'disabled:cursor-not-allowed disabled:border-border/[0.08] disabled:bg-transparent disabled:text-muted-soft ' +
    'disabled:hover:border-border/[0.08] disabled:hover:bg-transparent disabled:hover:text-muted-soft';

  /**
   * A single-page list has NO pagination footer.
   *
   * Every entity page passed this component unconditionally, so a list of eight
   * contacts still rendered "Page 1 of 1" with a Previous and a Next button.
   * Both were `disabled`, but the disabled styling above is deliberately
   * legible rather than faded — which is right for "you are on the first of
   * four pages" and wrong here, where it reads as two working controls that
   * silently do nothing however often you click them.
   *
   * There is also nothing to report: "Page 1 of 1" is a fact about a list that
   * is not paginated. So when there is only one page the whole footer goes,
   * and it comes back the moment a list outgrows a page.
   */
  if (lastPage <= 1) return null;

  return (
    <div className="flex items-center justify-between text-xs text-muted-soft">
      <span className="uppercase tracking-[0.1em]">
        Page {page} of {lastPage}
        {isFetching && page > 1 ? ' · refreshing…' : ''}
      </span>
      <div className="flex gap-2">
        <button type="button" onClick={onPrev} disabled={page === 1} className={btn}>
          Previous
        </button>
        <button type="button" onClick={onNext} disabled={page >= lastPage} className={btn}>
          Next
        </button>
      </div>
    </div>
  );
}

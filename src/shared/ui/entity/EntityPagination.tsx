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
  const btn =
    'rounded-pill border border-white/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted transition-colors hover:border-white/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-white/[0.08] disabled:hover:text-muted';

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

import { useCallback, useMemo, useState } from 'react';

// Tracks a set of selected row ids for a list page. Kept generic over the id
// string so it works for any entity. `pageIds` is the ids currently visible on
// the page — the header checkbox selects/clears exactly those, and the
// all-selected / partial states are computed against them.
export interface BulkSelection {
  selectedIds: readonly string[];
  count: number;
  isSelected: (id: string) => boolean;
  toggle: (id: string) => void;
  // Select all rows on the current page (or clear them if all are selected).
  toggleAllOnPage: (pageIds: readonly string[]) => void;
  // True when every page id is selected (drives the header checkbox checked state).
  allOnPageSelected: (pageIds: readonly string[]) => boolean;
  // True when some — but not all — page ids are selected (indeterminate state).
  someOnPageSelected: (pageIds: readonly string[]) => boolean;
  clear: () => void;
}

export function useBulkSelection(): BulkSelection {
  const [selected, setSelected] = useState<Set<string>>(() => new Set());

  const toggle = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const allOnPageSelected = useCallback(
    (pageIds: readonly string[]) =>
      pageIds.length > 0 && pageIds.every((id) => selected.has(id)),
    [selected],
  );

  const someOnPageSelected = useCallback(
    (pageIds: readonly string[]) =>
      pageIds.some((id) => selected.has(id)) && !pageIds.every((id) => selected.has(id)),
    [selected],
  );

  const toggleAllOnPage = useCallback(
    (pageIds: readonly string[]) => {
      setSelected((prev) => {
        const next = new Set(prev);
        const allSelected = pageIds.length > 0 && pageIds.every((id) => next.has(id));
        if (allSelected) pageIds.forEach((id) => next.delete(id));
        else pageIds.forEach((id) => next.add(id));
        return next;
      });
    },
    [],
  );

  const clear = useCallback(() => setSelected(new Set()), []);

  const selectedIds = useMemo(() => Array.from(selected), [selected]);

  return {
    selectedIds,
    count: selectedIds.length,
    isSelected: (id) => selected.has(id),
    toggle,
    toggleAllOnPage,
    allOnPageSelected,
    someOnPageSelected,
    clear,
  };
}

import { useMemo } from 'react';
import type { EntitySelectOption } from '@/shared/ui/entity';

/**
 * Builds the option lists that `type: 'lookup'` form fields render.
 *
 * WHY THIS EXISTS: every foreign-key field in this app used to be a free-text box
 * captioned "… id (UUID)". An end user has no way to obtain a UUID, so those
 * fields were unusable — the only way to fill one was to read it out of the
 * database. Each hook below turns a record list into {value: id, label: something
 * a human recognises}, so a reference is chosen, never transcribed.
 *
 * Each hook returns `undefined` while its list is loading, which is what makes the
 * picker show "Loading…" and stay disabled rather than looking like an empty list.
 *
 * Lists are capped at the backend's MAX_LIMIT (common/dto/pagination.dto.ts) —
 * asking for more is a 400, not a bigger page. Past this many entries a <select>
 * is the wrong control anyway: the right answer is a searchable typeahead, not a
 * larger dropdown. If a tenant outgrows it, upgrade the control rather than the
 * number — a silently truncated picker is worse than a slow one.
 */
export const LOOKUP_PAGE_SIZE = 100;

/**
 * Turns a fetched record list into sorted picker options.
 *
 * Takes the ALREADY-FETCHED rows rather than a query hook: RTK Query hooks must be
 * called unconditionally at a fixed position, so each caller owns its own
 * `useListXQuery({page:1, limit: LOOKUP_PAGE_SIZE, ...})` call and passes the
 * result here. That also keeps the `skip` option in the caller's hands.
 *
 * Returns `undefined` while the list is still loading — that is the signal the
 * lookup control uses to stay disabled and show "Loading…", so a slow list is
 * never mistaken for an empty one.
 */
export function useLookupOptions<T extends { id: string }>(
  rows: readonly T[] | undefined,
  isLoading: boolean,
  toLabel: (record: T) => string,
): readonly EntitySelectOption[] | undefined {
  return useMemo(() => {
    // Only "loading" yields undefined. A settled query with no rows — including a
    // failed one — yields an empty array, so the picker enables and reads as
    // "nothing to choose" instead of hanging on "Loading…" forever.
    if (isLoading) return undefined;
    if (!rows) return [];
    return [...rows]
      .map((record) => ({ value: record.id, label: toLabel(record) }))
      .sort((a, b) => a.label.localeCompare(b.label));
    // toLabel is a stable module-level function at every call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, isLoading]);
}

/** id -> display name, for READING a stored reference back out. */
export type NameTable = ReadonlyMap<string, string>;

/**
 * The display-side counterpart to `useLookupOptions`.
 *
 * `useLookupOptions` is for WRITING a reference (a picker); this is for READING one
 * back — turning the id a row stores into the name a column shows. Several list
 * views were rendering the id itself, which is how a raw uuid ended up in a Source
 * column and as a note's author.
 *
 * Resolve with `displayName()`, never with `?? id`: a uuid on screen is worse than
 * a blank, because it looks like data while telling the user nothing.
 */
export function useNameTable<T extends { id: string }>(
  rows: readonly T[] | undefined,
  toLabel: (record: T) => string,
): NameTable {
  return useMemo(() => {
    return new Map((rows ?? []).map((record) => [record.id, toLabel(record)]));
    // toLabel is a stable module-level function at every call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows]);
}

/**
 * Resolves an id against a name table. An id we cannot resolve yields '' so the
 * caller renders an empty cell.
 *
 * Name tables are capped at one page (LOOKUP_PAGE_SIZE), so a partially resolved
 * table is a NORMAL state, not an error — which is exactly why the fallback must
 * not be the id.
 */
export function displayName(
  table: NameTable | undefined,
  id: string | null | undefined,
): string {
  if (!id) return '';
  return table?.get(id) ?? '';
}

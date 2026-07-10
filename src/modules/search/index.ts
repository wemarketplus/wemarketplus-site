// Client-side global search / command palette (Cmd/Ctrl+K). Federates over the
// existing contacts / companies / prospects list queries — there is no backend
// global-search endpoint. GlobalSearch is the shell entry point; the rest are
// exported for tests / bespoke wiring.
export { GlobalSearch } from './GlobalSearch';
export { CommandPalette } from './CommandPalette';
export { useCommandPalette } from './useCommandPalette';
export { useGlobalSearch } from './useGlobalSearch';
export type { SearchResult, SearchGroup, SearchGroupKey } from './types';

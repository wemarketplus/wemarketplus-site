import type { LucideIcon } from 'lucide-react';

// A single flattened result row shown in the palette. `to` is the route the
// result navigates to (list page, optionally with a deep-link query string).
export interface SearchResult {
  id: string;
  // The entity group this result belongs to (drives the section header + icon).
  group: SearchGroupKey;
  title: string;
  // Optional secondary line (email, stage, status, …).
  subtitle?: string;
  to: string;
}

export type SearchGroupKey = 'contacts' | 'companies' | 'prospects';

export interface SearchGroupMeta {
  key: SearchGroupKey;
  label: string;
  icon: LucideIcon;
}

// A group of results rendered under one header. `isLoading` lets the palette
// show a per-group spinner while that entity's query is still in flight.
export interface SearchGroup extends SearchGroupMeta {
  results: SearchResult[];
  isLoading: boolean;
}

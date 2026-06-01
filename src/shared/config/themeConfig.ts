// Theme tokens — see also src/index.css (where the CSS custom properties
// actually live) and tailwind.config.js (which exposes them as Tailwind
// utilities). This file is the TS-visible registry of token names.
//
// The app is dark-only today. ThemeMode is kept as a union for forward
// compatibility, but consumers should treat the resolved mode as `'dark'`.
export type ThemeMode = 'dark';

export const DEFAULT_THEME: ThemeMode = 'dark';

export const SEMANTIC_TOKENS = [
  'bg',
  'ink',
  'surface',
  'surface-elevated',
  'surface-raised',
  'foreground',
  'muted',
  'muted-soft',
  'faint',
  'border',
  'border-strong',
  'primary',
  'primary-hover',
  'primary-foreground',
  'azure',
  'amber',
  'lime',
  'success',
  'warning',
  'destructive',
  'destructive-foreground',
] as const;

export type SemanticToken = (typeof SEMANTIC_TOKENS)[number];

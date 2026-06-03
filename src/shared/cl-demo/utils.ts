// Pure helpers shared across the CommunityLink demo modules. No side effects.

// Capitalizes the first character (reference cap()).
export function cap(s: string): string {
  if (!s) return '';
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Today as an ISO date string (YYYY-MM-DD) — reference todayIso(). Shared by
// the demo slices/forms that stamp newly created records.
export function todayIso(): string {
  return new Date().toISOString().split('T')[0];
}

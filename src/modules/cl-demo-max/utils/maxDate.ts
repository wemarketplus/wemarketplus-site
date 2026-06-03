// Date helpers for the Max demo. No mutation side effects.

// Today's date as a yyyy-mm-dd string (reference's todayIso()).
export function todayIso(): string {
  return new Date().toISOString().split('T')[0];
}

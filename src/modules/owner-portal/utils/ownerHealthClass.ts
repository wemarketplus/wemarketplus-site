// Health score → semantic color class. Used by customer and usage tables.
export function healthToneClass(score: number): string {
  if (score >= 0.75) return 'text-success';
  if (score >= 0.45) return 'text-warning';
  return 'text-destructive';
}

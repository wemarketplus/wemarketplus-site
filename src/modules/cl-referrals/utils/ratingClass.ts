export function ratingToneClass(rating: number): string {
  if (rating >= 4) return 'text-success';
  if (rating >= 3) return 'text-warning';
  return 'text-muted-soft';
}

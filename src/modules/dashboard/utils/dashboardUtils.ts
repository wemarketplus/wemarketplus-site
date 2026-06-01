import type { DashboardStatCard } from '../types/dashboardTypes';

// Returns a greeting based on the current hour. Pure utility — pulled out
// of the hook so the hook stays orchestration-only.
export function timeBasedGreeting(date: Date = new Date()): string {
  const hour = date.getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
}

// Maps a stat's `tone` token to the dot-indicator className used on its tile.
export function statToneDotClass(tone: DashboardStatCard['tone']): string {
  switch (tone) {
    case 'azure':
      return 'bg-azure';
    case 'amber':
      return 'bg-amber';
    case 'warning':
      return 'bg-warning';
    case 'destructive':
      return 'bg-destructive';
    case 'success':
      return 'bg-success';
    case 'primary':
    default:
      return 'bg-primary';
  }
}

import type { Strength } from '../types/authTypes';

// Mirrors wemarketplus-backend/src/users/users.constants.ts.
export const PASSWORD_MIN_LENGTH = 8;
export const NAME_MIN_LENGTH = 1;
export const NAME_MAX_LENGTH = 120;

export const AUTH_TAGS = {
  Me: 'Auth.Me',
} as const;

export const AUTH_REDIRECT_DELAY_MS = 1500;

export const STRENGTH_BAR: Record<Strength, { width: string; color: string; label: string }> = {
  none: { width: 'w-0', color: '', label: '' },
  weak: { width: 'w-1/3', color: 'bg-[#e05555]', label: 'Weak' },
  mid: { width: 'w-2/3', color: 'bg-[#fbbf24]', label: 'Medium' },
  strong: { width: 'w-full', color: 'bg-[#8cff66]', label: 'Strong ✓' },
};

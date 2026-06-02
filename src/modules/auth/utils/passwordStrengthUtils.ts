import type { Rule, Strength } from '../types/authTypes';

export const PASSWORD_RULES: readonly Rule[] = [
  { key: 'r1', label: 'At least 8 characters', test: (v) => v.length >= 8 },
  { key: 'r2', label: 'At least one uppercase letter', test: (v) => /[A-Z]/.test(v) },
  { key: 'r3', label: 'At least one number', test: (v) => /[0-9]/.test(v) },
  { key: 'r4', label: 'At least one special character', test: (v) => /[^a-zA-Z0-9]/.test(v) },
];

export function strengthOf(v: string): Strength {
  if (!v) return 'none';
  const strong =
    v.length >= 10 && /[A-Z]/.test(v) && /[0-9]/.test(v) && /[^a-zA-Z0-9]/.test(v);
  const mid = v.length >= 8 && (/[A-Z]/.test(v) || /[0-9]/.test(v));
  if (strong) return 'strong';
  if (mid) return 'mid';
  return 'weak';
}

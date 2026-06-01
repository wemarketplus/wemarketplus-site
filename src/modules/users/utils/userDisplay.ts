import type { UserRecord } from '../types/usersTypes';

export const fullName = (u: Pick<UserRecord, 'firstName' | 'lastName'>): string =>
  `${u.firstName} ${u.lastName}`.trim();

export const initials = (u: Pick<UserRecord, 'firstName' | 'lastName'>): string => {
  const first = u.firstName?.[0] ?? '';
  const last = u.lastName?.[0] ?? '';
  return `${first}${last}`.toUpperCase() || '?';
};

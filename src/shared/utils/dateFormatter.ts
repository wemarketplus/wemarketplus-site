import { format, formatDistanceToNow, parseISO } from 'date-fns';

const toDate = (value: string | Date): Date =>
  typeof value === 'string' ? parseISO(value) : value;

export const formatDate = (value: string | Date, pattern = 'PP'): string =>
  format(toDate(value), pattern);

export const formatDateTime = (value: string | Date): string =>
  format(toDate(value), 'PPp');

export const formatRelative = (value: string | Date): string =>
  formatDistanceToNow(toDate(value), { addSuffix: true });

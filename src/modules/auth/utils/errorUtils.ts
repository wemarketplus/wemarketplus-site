import type { ApiErrorPayload } from '@/shared/types';

// RTK Query errors come back as `{ status, data }`. `data` matches the backend's
// AllExceptionsFilter shape. Flatten that into a single user-facing string.
export function extractApiErrorMessage(error: unknown, fallback = 'Something went wrong'): string {
  if (!error || typeof error !== 'object') return fallback;

  const maybe = error as { data?: Partial<ApiErrorPayload>; error?: string; status?: number };

  if (maybe.data?.message) {
    return Array.isArray(maybe.data.message) ? maybe.data.message.join(', ') : maybe.data.message;
  }

  if (typeof maybe.error === 'string') return maybe.error;
  if (typeof maybe.status === 'number') return `Request failed (${maybe.status})`;

  return fallback;
}

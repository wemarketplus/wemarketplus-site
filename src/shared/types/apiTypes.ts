// Shapes the wemarketplus-backend uses for every response. See
// `wemarketplus-backend/src/common/interceptors/transform.interceptor.ts` and
// `src/common/filters/all-exceptions.filter.ts`.

export interface ApiEnvelope<T> {
  data: T;
}

export interface PaginatedPayload<T> {
  data: T[];
  total: number;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
}

export interface ApiErrorPayload {
  statusCode: number;
  message: string | string[];
  timestamp: string;
  path: string;
}

import type { ReactNode } from 'react';
import type { FetchBaseQueryError } from '@reduxjs/toolkit/query';
import type { SerializedError } from '@reduxjs/toolkit';
import { Alert } from '@/shared/ui/data-display';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';

// Standard loading / error / 403 gate for the live owner-portal pages. The
// /owner/* routes require SuperAdmin on the backend, so a 403 is surfaced with
// a dedicated message rather than the generic error text.
interface OwnerQueryStateProps {
  isLoading: boolean;
  error: FetchBaseQueryError | SerializedError | undefined;
  children: ReactNode;
}

function isForbidden(
  error: FetchBaseQueryError | SerializedError | undefined,
): boolean {
  return Boolean(error && 'status' in error && error.status === 403);
}

export function OwnerQueryState({ isLoading, error, children }: OwnerQueryStateProps) {
  if (isLoading) {
    return (
      <div className="rounded-[12px] border border-white/[0.08] bg-surface p-10 text-center text-sm text-muted">
        Loading…
      </div>
    );
  }

  if (error) {
    if (isForbidden(error)) {
      return (
        <Alert tone="y">
          You need platform owner (SuperAdmin) access to view this data.
        </Alert>
      );
    }
    return <Alert tone="r">{extractApiErrorMessage(error, 'Failed to load data.')}</Alert>;
  }

  return <>{children}</>;
}

import { useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerLiveCustomersTable } from '../components/OwnerLiveCustomersTable';
import { OwnerQueryState } from '../components/OwnerQueryState';
import { useImpersonation } from '../hooks/useImpersonation';
import {
  useListOwnerCustomersQuery,
  useSuspendCustomerMutation,
} from '../api/ownerPortalApi';
import type { OwnerCustomer } from '../types/ownerPortalApiTypes';

const PAGE_SIZE = 20;

export function OwnerCustomersPage() {
  const [page, setPage] = useState(1);
  const { data, isLoading, isFetching, error } = useListOwnerCustomersQuery({
    page,
    limit: PAGE_SIZE,
  });
  const [suspendCustomer, { isLoading: isSuspending }] = useSuspendCustomerMutation();
  const [suspendingId, setSuspendingId] = useState<string | null>(null);
  const { start: startImpersonation, isStarting } = useImpersonation();
  const [impersonatingId, setImpersonatingId] = useState<string | null>(null);

  const customers = data?.data ?? [];
  const total = data?.total ?? 0;
  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const onSuspend = async (customer: OwnerCustomer) => {
    setSuspendingId(customer.id);
    try {
      await suspendCustomer(customer.id).unwrap();
      toast.success(`Suspended ${customer.name}.`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not suspend this account.'));
    } finally {
      setSuspendingId(null);
    }
  };

  const onImpersonate = async (customer: OwnerCustomer) => {
    setImpersonatingId(customer.id);
    try {
      const ok = await startImpersonation(customer.id);
      if (ok) {
        // Land in the impersonated workspace. A hard navigation resets RTK Query
        // caches so every request refetches under the new (tenant) token.
        window.location.assign('/dashboard');
      }
    } finally {
      setImpersonatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Customer database"
        description="Every tenant account with subscription and activation state."
      />

      <OwnerQueryState isLoading={isLoading} error={error}>
        <OwnerLiveCustomersTable
          customers={customers}
          onSuspend={onSuspend}
          suspendingId={isSuspending ? suspendingId : null}
          onImpersonate={onImpersonate}
          impersonatingId={isStarting ? impersonatingId : null}
        />

        <div className="flex items-center justify-between text-xs text-muted-soft">
          <span className="uppercase tracking-label">
            Page {page} of {lastPage}
            {isFetching && page > 1 ? ' · refreshing…' : ''}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="rounded-pill border border-border/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-label text-muted transition-colors hover:border-border/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-border/[0.08] disabled:hover:text-muted"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(lastPage, p + 1))}
              disabled={page >= lastPage}
              className="rounded-pill border border-border/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-label text-muted transition-colors hover:border-border/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-border/[0.08] disabled:hover:text-muted"
            >
              Next
            </button>
          </div>
        </div>
      </OwnerQueryState>
    </div>
  );
}

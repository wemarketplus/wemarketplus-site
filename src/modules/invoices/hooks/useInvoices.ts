import { useEffect, useMemo, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListInvoicesQuery,
  useCreateInvoiceMutation,
  useUpdateInvoiceMutation,
} from '../api/invoicesApi';
import { INVOICES_PAGE_SIZE } from '../constants/invoicesConstants';
import { toCreateInvoice, toUpdateInvoice } from '../utils/invoicesUtils';
import type { InvoiceStatus } from '../constants/invoicesConstants';
import type { InvoiceFormValues } from '../schema/invoiceSchema';
import type { InvoiceRecord } from '../types/invoicesTypes';

// The invoices backend exposes no DELETE, so useEntityCrud's `remove` is a stub
// that is never reached — the table renders no delete action.
const noRemove = () => ({
  unwrap: () => Promise.reject(new Error('Invoices cannot be deleted')),
});

// Single hook the InvoicesPage consumes: composes the paginated query (with a
// server-side status filter + client-side search) and the shared CRUD
// orchestration (create + update only).
export function useInvoices() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<InvoiceStatus | ''>('');
  const debouncedSearch = useDebounce(search, 250);

  const needle = debouncedSearch.trim().toLowerCase();
  const filter = useMemo(
    () => (i: InvoiceRecord) => {
      if (!needle) return true;
      return (
        i.companyName.toLowerCase().includes(needle) ||
        i.invoiceNumber.toLowerCase().includes(needle) ||
        (i.feeModel?.toLowerCase().includes(needle) ?? false)
      );
    },
    [needle],
  );

  const [page, setPage] = useState(1);
  // status is a server filter — reset to page 1 whenever it changes.
  useEffect(() => setPage(1), [status]);

  const query = useListInvoicesQuery({
    page,
    limit: INVOICES_PAGE_SIZE,
    ...(status ? { status } : {}),
  });

  const list = usePaginatedList<InvoiceRecord>(query, {
    pageSize: INVOICES_PAGE_SIZE,
    filter,
  });

  const [createInvoice, createState] = useCreateInvoiceMutation();
  const [updateInvoice, updateState] = useUpdateInvoiceMutation();

  const crud = useEntityCrud<
    InvoiceRecord,
    ReturnType<typeof toCreateInvoice>,
    ReturnType<typeof toUpdateInvoice>
  >({
    noun: 'invoice',
    create: createInvoice,
    update: updateInvoice,
    remove: noRemove,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (i) => i.invoiceNumber,
  });

  const submit = (values: InvoiceFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateInvoice(values))
      : crud.submitCreate(toCreateInvoice(values));

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    isMutating: createState.isLoading || updateState.isLoading,
    crud,
    submit,
  };
}

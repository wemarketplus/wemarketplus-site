// Invoices CRUD (create + edit; no delete) built on the shared entity kit
// (@/shared/ui/entity). Mirrors ContactsPage. Mutations require the backend
// `manage_invoices` permission; a non-permitted user's create/edit gets a 403
// surfaced via the error toast in useEntityCrud. We gate the Add button to
// staff, matching the contacts/users convention.
import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { InvoicesFilters } from '../components/InvoicesFilters';
import { InvoicesTable } from '../components/InvoicesTable';
import { InvoiceFormModal } from '../components/InvoiceFormModal';
import { useInvoices } from '../hooks/useInvoices';

export function InvoicesPage() {
  const {
    rows,
    total,
    page,
    lastPage,
    prevPage,
    nextPage,
    isLoading,
    isFetching,
    error,
    search,
    setSearch,
    status,
    setStatus,
    isMutating,
    crud,
    submit,
  } = useInvoices();

  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  return (
    <>
      <EntityListPage
        title="Invoices"
        subtitle={`${total} ${total === 1 ? 'invoice' : 'invoices'}`}
        addLabel="New invoice"
        onAdd={canCreate ? crud.openCreate : undefined}
        filters={
          <InvoicesFilters
            search={search}
            onSearch={setSearch}
            status={status}
            onStatus={setStatus}
          />
        }
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load invoices"
        pagination={
          <EntityPagination
            page={page}
            lastPage={lastPage}
            isFetching={isFetching}
            onPrev={prevPage}
            onNext={nextPage}
          />
        }
      >
        <InvoicesTable invoices={rows} isMutating={isMutating} onEdit={crud.openEdit} />
      </EntityListPage>

      <InvoiceFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}

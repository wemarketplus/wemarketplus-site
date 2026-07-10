// Built on the shared entity kit (@/shared/ui/entity) — see
// modules/contacts/pages/ContactsPage.tsx for the annotated reference. Companies
// adds two twists over contacts: server-side search + status filters, and an
// admin-only Dedup action in the header.
import { Merge } from 'lucide-react';
import { ADMIN_ONLY, STAFF_ROLES, useRole } from '@/shared/rbac';
import { Button } from '@/shared/ui/core';
import { BulkActionBar, EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { CompaniesFilters } from '../components/CompaniesFilters';
import { CompaniesTable } from '../components/CompaniesTable';
import { CompanyFormModal } from '../components/CompanyFormModal';
import { useCompanies } from '../hooks/useCompanies';

export function CompaniesPage() {
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
    dedup,
    isDeduping,
    selection,
    bulkDelete,
  } = useCompanies();

  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);
  const canDedup = isAny(ADMIN_ONLY);
  // Bulk delete follows the same Admin/Owner gate as single delete.
  const canDelete = isAny(ADMIN_ONLY);

  const pageIds = rows.map((c) => c.id);
  const runBulkDelete = async () => {
    const result = await bulkDelete.run(selection.selectedIds);
    if (result) selection.clear();
  };

  return (
    <>
      <EntityListPage
        title="Companies"
        subtitle={`${total} employer ${total === 1 ? 'company' : 'companies'}`}
        addLabel="Add company"
        onAdd={canCreate ? crud.openCreate : undefined}
        actions={
          canDedup ? (
            <Button variant="ghost" onClick={dedup} disabled={isDeduping}>
              <Merge className="h-4 w-4" /> {isDeduping ? 'Merging…' : 'Dedup'}
            </Button>
          ) : undefined
        }
        filters={
          <CompaniesFilters
            search={search}
            onSearch={setSearch}
            status={status}
            onStatus={setStatus}
          />
        }
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load companies"
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
        {canDelete && (
          <BulkActionBar
            count={selection.count}
            noun="company"
            nounPlural="companies"
            onDelete={runBulkDelete}
            onClear={selection.clear}
            isDeleting={bulkDelete.isDeleting}
            progress={bulkDelete.progress}
          />
        )}
        <CompaniesTable
          companies={rows}
          isMutating={isMutating || bulkDelete.isDeleting}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
          onAdd={canCreate ? crud.openCreate : undefined}
          hasFilters={Boolean(search) || Boolean(status)}
          selection={
            canDelete
              ? {
                  isSelected: selection.isSelected,
                  toggle: selection.toggle,
                  allSelected: selection.allOnPageSelected(pageIds),
                  someSelected: selection.someOnPageSelected(pageIds),
                  toggleAll: () => selection.toggleAllOnPage(pageIds),
                }
              : undefined
          }
        />
      </EntityListPage>

      <CompanyFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}

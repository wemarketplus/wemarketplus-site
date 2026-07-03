// Reference implementation of the shared "entity CRUD page" kit
// (@/shared/ui/entity). A new list+create+edit+delete module (funding,
// locations, territories, …) can be built by cloning this file plus:
//   - schema/contactSchema.ts   (zod schema + form-values type)
//   - constants (EntityField[] + page size)
//   - utils (form <-> DTO mapping via opt/optNum)
//   - components/*Table + *Filters + *FormModal
//   - hooks/useContacts.ts      (usePaginatedList + useEntityCrud composition)
// See @/shared/ui/entity/index.ts for the full checklist.
import { ADMIN_ONLY, STAFF_ROLES, useRole } from '@/shared/rbac';
import { BulkActionBar, EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { ContactsFilters } from '../components/ContactsFilters';
import { ContactsTable } from '../components/ContactsTable';
import { ContactFormModal } from '../components/ContactFormModal';
import { useContacts } from '../hooks/useContacts';

export function ContactsPage() {
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
    recordType,
    setRecordType,
    isMutating,
    crud,
    submit,
    selection,
    bulkDelete,
  } = useContacts();

  // Create is staff-level; the backend allows any authenticated user to POST a
  // contact, but we mirror the users-page convention of gating the Add button.
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);
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
        title="Contacts"
        subtitle={`${total} ${total === 1 ? 'contact' : 'contacts'} across your records`}
        addLabel="Add contact"
        onAdd={canCreate ? crud.openCreate : undefined}
        filters={
          <ContactsFilters
            search={search}
            onSearch={setSearch}
            recordType={recordType}
            onRecordType={setRecordType}
          />
        }
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load contacts"
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
            noun="contact"
            onDelete={runBulkDelete}
            onClear={selection.clear}
            isDeleting={bulkDelete.isDeleting}
            progress={bulkDelete.progress}
          />
        )}
        <ContactsTable
          contacts={rows}
          isMutating={isMutating || bulkDelete.isDeleting}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
          onAdd={canCreate ? crud.openCreate : undefined}
          hasFilters={Boolean(search) || Boolean(recordType)}
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

      <ContactFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}

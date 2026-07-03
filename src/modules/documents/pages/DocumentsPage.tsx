import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { DocumentsScopePicker } from '../components/DocumentsScopePicker';
import { DocumentsTable } from '../components/DocumentsTable';
import { DocumentFormModal } from '../components/DocumentFormModal';
import { useDocuments } from '../hooks/useDocuments';

export function DocumentsPage() {
  const {
    scope,
    setScope,
    parentId,
    setParentId,
    validParent,
    showEmptyHint,
    rows,
    total,
    page,
    lastPage,
    prevPage,
    nextPage,
    isLoading,
    isFetching,
    error,
    createOpen,
    openCreate,
    closeCreate,
    isSaving,
    isMutating,
    submitCreate,
    confirmDelete,
  } = useDocuments();

  // Create is staff-level; mirror the users-page convention of gating the Add
  // button (the backend allows any authenticated user to POST a document).
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  const empty = showEmptyHint
    ? 'Pick a scope and enter a valid parent id (UUID) to load documents.'
    : 'No documents recorded for this parent yet.';

  return (
    <>
      <EntityListPage
        title="Documents"
        subtitle={
          validParent
            ? `${total} ${total === 1 ? 'document' : 'documents'} on file`
            : 'Metadata records referencing files stored in Drive'
        }
        addLabel="Record document"
        onAdd={canCreate && validParent ? openCreate : undefined}
        filters={
          <DocumentsScopePicker
            scope={scope}
            onScope={setScope}
            parentId={parentId}
            onParentId={setParentId}
            validParent={validParent}
          />
        }
        isLoading={validParent && isLoading}
        error={error}
        errorFallback="Failed to load documents"
        pagination={
          validParent ? (
            <EntityPagination
              page={page}
              lastPage={lastPage}
              isFetching={isFetching}
              onPrev={prevPage}
              onNext={nextPage}
            />
          ) : undefined
        }
      >
        <DocumentsTable
          documents={validParent ? rows : []}
          isMutating={isMutating}
          onDelete={confirmDelete}
          empty={empty}
        />
      </EntityListPage>

      <DocumentFormModal
        open={createOpen}
        isSaving={isSaving}
        onClose={closeCreate}
        onSubmit={submitCreate}
      />
    </>
  );
}

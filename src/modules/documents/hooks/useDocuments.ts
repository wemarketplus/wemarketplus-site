import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { usePaginatedList } from '@/shared/ui/entity';
import {
  useListEmployerDocumentsQuery,
  useCreateEmployerDocumentMutation,
  useDeleteEmployerDocumentMutation,
  useListWibDocumentsQuery,
  useCreateWibDocumentMutation,
  useDeleteWibDocumentMutation,
} from '../api/documentsApi';
import { DOCUMENT_SCOPE, DOCUMENTS_PAGE_SIZE, type DocumentScope } from '../constants/documentsConstants';
import { toCreateDocument } from '../utils/documentsUtils';
import type { DocumentFormValues } from '../schema/documentSchema';
import type { DocumentRecord } from '../types/documentsTypes';

// Naive UUID v4-ish check so we only fire the (parent-required) list query once a
// plausible id is entered; the backend list endpoints reject a missing/blank id.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// The documents domain has no single "list all" endpoint and no update endpoint —
// both stores are parent-scoped and support only list/create/delete. This hook
// picks a scope (employer vs WIB) + parent id, then wires the matching
// list/create/delete triggers and orchestrates create/delete with toasts
// (useEntityCrud is not used here because it requires an update mutation).
export function useDocuments() {
  const [scope, setScope] = useState<DocumentScope>(DOCUMENT_SCOPE.Employer);
  const [parentId, setParentId] = useState('');
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);

  const validParent = UUID_RE.test(parentId.trim());
  const trimmedParent = parentId.trim();

  // Reset paging whenever the scope or parent changes.
  useEffect(() => setPage(1), [scope, trimmedParent]);

  const employerQuery = useListEmployerDocumentsQuery(
    { companyId: trimmedParent, page, limit: DOCUMENTS_PAGE_SIZE },
    { skip: scope !== DOCUMENT_SCOPE.Employer || !validParent },
  );
  const wibQuery = useListWibDocumentsQuery(
    { wibId: trimmedParent, page, limit: DOCUMENTS_PAGE_SIZE },
    { skip: scope !== DOCUMENT_SCOPE.Wib || !validParent },
  );

  const query = scope === DOCUMENT_SCOPE.Employer ? employerQuery : wibQuery;
  const list = usePaginatedList<DocumentRecord>(query, { pageSize: DOCUMENTS_PAGE_SIZE });

  const [createEmployerDoc, createEmployerState] = useCreateEmployerDocumentMutation();
  const [createWibDoc, createWibState] = useCreateWibDocumentMutation();
  const [deleteEmployerDoc, deleteEmployerState] = useDeleteEmployerDocumentMutation();
  const [deleteWibDoc, deleteWibState] = useDeleteWibDocumentMutation();

  const isSaving = createEmployerState.isLoading || createWibState.isLoading;
  const isMutating =
    isSaving || deleteEmployerState.isLoading || deleteWibState.isLoading;

  const submitCreate = async (values: DocumentFormValues): Promise<boolean> => {
    if (!validParent) {
      toast.error('Enter a valid parent id before recording a document.');
      return false;
    }
    const body = toCreateDocument(values);
    try {
      if (scope === DOCUMENT_SCOPE.Employer) {
        await createEmployerDoc({ companyId: trimmedParent, body }).unwrap();
      } else {
        await createWibDoc({ wibId: trimmedParent, body }).unwrap();
      }
      toast.success('Document recorded');
      setCreateOpen(false);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not record document. Please try again.'));
      return false;
    }
  };

  const confirmDelete = async (doc: DocumentRecord): Promise<void> => {
    if (!window.confirm(`Delete ${doc.fileName}? This cannot be undone.`)) return;
    try {
      if (scope === DOCUMENT_SCOPE.Employer) {
        await deleteEmployerDoc(doc.id).unwrap();
      } else {
        await deleteWibDoc(doc.id).unwrap();
      }
      toast.success(`Deleted ${doc.fileName}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not delete document.'));
    }
  };

  const canList = validParent;
  const showEmptyHint = useMemo(() => !validParent, [validParent]);

  return {
    scope,
    setScope,
    parentId,
    setParentId,
    validParent,
    canList,
    showEmptyHint,
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    createOpen,
    openCreate: () => setCreateOpen(true),
    closeCreate: () => setCreateOpen(false),
    isSaving,
    isMutating,
    submitCreate,
    confirmDelete,
  };
}

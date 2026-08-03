import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { usePaginatedList } from '@/shared/ui/entity';
import {
  useListEmployerDocumentsQuery,
  useCreateEmployerDocumentMutation,
  useDeleteEmployerDocumentMutation,
} from '../api/documentsApi';
import { confirm } from '@/shared/ui/feedback';
import { DOCUMENTS_PAGE_SIZE } from '../constants/documentsConstants';
import { toCreateDocument } from '../utils/documentsUtils';
import type { DocumentFormValues } from '../schema/documentSchema';
import type { DocumentRecord } from '../types/documentsTypes';

// The documents domain has no "list all" endpoint and no update endpoint — the
// store is parent-scoped and supports only list/create/delete. This hook takes the
// selected company and wires list/create/delete with toasts (useEntityCrud is not
// used here because it requires an update mutation).
export function useDocuments() {
  const [parentId, setParentId] = useState('');
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);

  const trimmedParent = parentId.trim();
  // The picker only ever yields a real record id, so "something is selected" is
  // now the whole validity check — no UUID shape-guessing needed.
  const validParent = trimmedParent !== '';

  // Reset paging whenever the selected company changes.
  useEffect(() => setPage(1), [trimmedParent]);

  const query = useListEmployerDocumentsQuery(
    { companyId: trimmedParent, page, limit: DOCUMENTS_PAGE_SIZE },
    { skip: !validParent },
  );
  const list = usePaginatedList<DocumentRecord>(query, { pageSize: DOCUMENTS_PAGE_SIZE });

  const [createEmployerDoc, createEmployerState] = useCreateEmployerDocumentMutation();
  const [deleteEmployerDoc, deleteEmployerState] = useDeleteEmployerDocumentMutation();

  const isSaving = createEmployerState.isLoading;
  const isMutating = isSaving || deleteEmployerState.isLoading;

  const submitCreate = async (values: DocumentFormValues): Promise<boolean> => {
    if (!validParent) {
      toast.error('Select a company before recording a document.');
      return false;
    }
    const body = toCreateDocument(values);
    try {
      await createEmployerDoc({ companyId: trimmedParent, body }).unwrap();
      toast.success('Document recorded');
      setCreateOpen(false);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not record document. Please try again.'));
      return false;
    }
  };

  const confirmDelete = async (doc: DocumentRecord): Promise<void> => {
    const ok = await confirm({
      title: `Delete ${doc.fileName}?`,
      body: 'The document record is removed here. The file itself stays in Drive.',
      confirmLabel: 'Delete record',
    });
    if (!ok) return;
    try {
      await deleteEmployerDoc(doc.id).unwrap();
      toast.success(`Deleted ${doc.fileName}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not delete document.'));
    }
  };

  const canList = validParent;
  const showEmptyHint = useMemo(() => !validParent, [validParent]);

  return {
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

import { useEffect, useMemo, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import {
  usePaginatedList,
  useEntityCrud,
  useBulkSelection,
  useBulkDelete,
} from '@/shared/ui/entity';
import {
  useListContactsQuery,
  useCreateContactMutation,
  useUpdateContactMutation,
  useDeleteContactMutation,
} from '../api/contactsApi';
import { CONTACTS_PAGE_SIZE } from '../constants/contactsConstants';
import { toCreateContact, toUpdateContact } from '../utils/contactsUtils';
import type { ContactFormValues } from '../schema/contactSchema';
import type { ContactRecord } from '../types/contactsTypes';

// Single hook the ContactsPage consumes: composes the paginated query (with a
// server-side recordType filter + client-side search) and the shared CRUD
// orchestration. This is the template a new module clones.
export function useContacts() {
  const [search, setSearch] = useState('');
  const [recordType, setRecordType] = useState('');
  const debouncedSearch = useDebounce(search, 250);
  const debouncedType = useDebounce(recordType, 250);

  const needle = debouncedSearch.trim().toLowerCase();
  const filter = useMemo(
    () => (c: ContactRecord) => {
      if (!needle) return true;
      return (
        c.name.toLowerCase().includes(needle) ||
        (c.email?.toLowerCase().includes(needle) ?? false) ||
        (c.title?.toLowerCase().includes(needle) ?? false)
      );
    },
    [needle],
  );

  // Page state lives here so it exists before the query runs and can be fed
  // straight into it. `nextPage` clamps against the freshest lastPage each render.
  const [page, setPage] = useState(1);
  // recordType is a server filter — reset to page 1 whenever it changes.
  useEffect(() => setPage(1), [debouncedType]);

  const query = useListContactsQuery({
    page,
    limit: CONTACTS_PAGE_SIZE,
    ...(debouncedType.trim() ? { recordType: debouncedType.trim() } : {}),
  });

  const list = usePaginatedList<ContactRecord>(query, {
    pageSize: CONTACTS_PAGE_SIZE,
    filter,
  });

  const [createContact, createState] = useCreateContactMutation();
  const [updateContact, updateState] = useUpdateContactMutation();
  const [deleteContact, deleteState] = useDeleteContactMutation();

  const crud = useEntityCrud<
    ContactRecord,
    ReturnType<typeof toCreateContact>,
    ReturnType<typeof toUpdateContact>
  >({
    noun: 'contact',
    create: createContact,
    update: updateContact,
    remove: deleteContact,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (c) => c.name,
  });

  const submit = (values: ContactFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateContact(values))
      : crud.submitCreate(toCreateContact(values));

  // Bulk (multi-select) delete. Selection state + a sequential delete-per-id
  // runner reusing the same deleteContact mutation as single delete.
  const selection = useBulkSelection();
  const bulkDelete = useBulkDelete({ noun: 'contact', remove: deleteContact });

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    recordType,
    setRecordType,
    isMutating: deleteState.isLoading || createState.isLoading || updateState.isLoading,
    crud,
    submit,
    selection,
    bulkDelete,
  };
}

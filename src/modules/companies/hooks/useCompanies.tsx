import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { useDebounce } from '@/shared/hooks';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { confirm } from '@/shared/ui/feedback';
import {
  usePaginatedList,
  useEntityCrud,
  useBulkSelection,
  useBulkDelete,
} from '@/shared/ui/entity';
import {
  useListCompaniesQuery,
  useCreateCompanyMutation,
  useUpdateCompanyMutation,
  useDeleteCompanyMutation,
  useDedupCompaniesMutation,
  useLazyDedupPreviewQuery,
} from '../api/companiesApi';
import { COMPANIES_PAGE_SIZE } from '../constants/companiesConstants';
import { toCreateCompany, toUpdateCompany } from '../utils/companiesUtils';
import type { CompanyStatus } from '../constants/companiesConstants';
import type { CompanyFormValues } from '../schema/companySchema';
import type { CompanyDedupPreview, CompanyRecord } from '../types/companiesTypes';

// Companies list + CRUD + dedup. Both search and status are server-side filters
// (unlike contacts, whose search is client-side). Same shape as useContacts —
// this is the second reference for the entity kit.
export function useCompanies() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 250);

  const [page, setPage] = useState(1);
  // Both filters are server-side — reset to page 1 whenever either changes.
  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListCompaniesQuery({
    page,
    limit: COMPANIES_PAGE_SIZE,
    ...(debouncedSearch.trim() ? { search: debouncedSearch.trim() } : {}),
    ...(status ? { status: status as CompanyStatus } : {}),
  });

  const list = usePaginatedList<CompanyRecord>(query, { pageSize: COMPANIES_PAGE_SIZE });

  const [createCompany, createState] = useCreateCompanyMutation();
  const [updateCompany, updateState] = useUpdateCompanyMutation();
  const [deleteCompany, deleteState] = useDeleteCompanyMutation();
  const [dedupCompanies, dedupState] = useDedupCompaniesMutation();
  // Lazy on purpose: the preview is a scan, so it runs when Dedup is pressed —
  // not on every visit to the Companies page.
  const [fetchDedupPreview, dedupPreviewState] = useLazyDedupPreviewQuery();

  const crud = useEntityCrud<
    CompanyRecord,
    ReturnType<typeof toCreateCompany>,
    ReturnType<typeof toUpdateCompany>
  >({
    noun: 'company',
    create: createCompany,
    update: updateCompany,
    remove: deleteCompany,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (c) => c.companyName,
  });

  const submit = (values: CompanyFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateCompany(values))
      : crud.submitCreate(toCreateCompany(values));

  // Bulk (multi-select) delete — reuses deleteCompany for the sequential run.
  const selection = useBulkSelection();
  const bulkDelete = useBulkDelete({
    noun: 'company',
    nounPlural: 'companies',
    remove: deleteCompany,
  });

  /**
   * Merge duplicate company records.
   *
   * This asks the server what it WOULD do first, then names it in the dialog.
   * Dedup hard-deletes: it re-points each duplicate's locations and applications at
   * the keeper and then permanently removes the duplicate rows. The previous
   * version was a bare window.confirm reading "Merge duplicate company records?
   * This cannot be undone." — an irreversible bulk delete approved with no
   * indication of how many records, or which, would be destroyed. On a tenant with
   * no duplicates at all it still asked, and still sounded alarming.
   */
  const dedup = async () => {
    let preview: CompanyDedupPreview;
    try {
      preview = await fetchDedupPreview().unwrap();
    } catch (err) {
      toast.error(
        extractApiErrorMessage(err, 'Could not check for duplicate companies.'),
      );
      return;
    }

    if (preview.totalGroups === 0) {
      // Nothing to do is an answer, not an error — and not a scary prompt.
      toast.success('No duplicate companies found.');
      return;
    }

    const ok = await confirm({
      title: `Merge ${preview.totalGroups} duplicate ${
        preview.totalGroups === 1 ? 'group' : 'groups'
      }?`,
      body: (
        <div className="space-y-2">
          <p>
            {preview.wouldDelete}{' '}
            {preview.wouldDelete === 1 ? 'record' : 'records'} will be
            permanently deleted. Their locations and applications are moved to the
            record that is kept first.
          </p>
          <ul className="max-h-48 space-y-1 overflow-y-auto text-[12px]">
            {preview.groups.map((g) => (
              <li key={g.keeperName}>
                <span className="text-foreground">{g.keeperName}</span>
                <span className="text-muted-soft">
                  {' '}
                  keeps · removes {g.duplicateNames.join(', ')}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ),
      confirmLabel: `Merge and delete ${preview.wouldDelete}`,
    });
    if (!ok) return;

    try {
      const result = await dedupCompanies().unwrap();
      // Report `deleted`, not `merged`. `merged` counts keeper rows that gained a
      // field from their duplicate and is frequently 0 on a perfectly successful
      // run — which is how this toast came to say "Merged 0 duplicate companies"
      // immediately after permanently deleting a record.
      const { deleted, totalGroups, errors } = result;
      toast.success(
        `Merged ${totalGroups} duplicate ${
          totalGroups === 1 ? 'group' : 'groups'
        } · ${deleted} ${deleted === 1 ? 'record' : 'records'} deleted`,
      );
      // Partial failures were previously swallowed entirely — the run reported
      // success even when a group errored.
      if (errors.length > 0) {
        toast.error(
          `${errors.length} ${
            errors.length === 1 ? 'group' : 'groups'
          } could not be merged: ${errors[0]}`,
        );
      }
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not deduplicate companies.'));
    }
  };

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    isMutating:
      deleteState.isLoading || createState.isLoading || updateState.isLoading,
    crud,
    submit,
    dedup,
    // One busy flag for the whole gesture: checking for duplicates and merging
    // them are two requests but one user action.
    isDeduping: dedupState.isLoading || dedupPreviewState.isFetching,
    selection,
    bulkDelete,
  };
}

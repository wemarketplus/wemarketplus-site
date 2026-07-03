import { useState } from 'react';
import { Download } from 'lucide-react';
import { toast } from 'sonner';
import { useAppSelector } from '@/app/hooks';
import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { Button } from '@/shared/ui/core';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { TrainingProvidersFilters } from '../components/TrainingProvidersFilters';
import { TrainingProvidersTable } from '../components/TrainingProvidersTable';
import { TrainingProviderFormModal } from '../components/TrainingProviderFormModal';
import { useTrainingProviders } from '../hooks/useTrainingProviders';
import {
  downloadTrainingExport,
  trainingProvidersCsvUrl,
  trainingProvidersXlsxUrl,
} from '../utils/trainingExportUrls';

export function TrainingProvidersPage() {
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
    isMutating,
    crud,
    submit,
  } = useTrainingProviders();

  // Create is staff-level; mirror the users-page convention of gating the Add
  // button (the backend allows any authenticated user to POST a provider).
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  // Bearer-authenticated blob downloads (see downloadTrainingExport).
  const token = useAppSelector((s) => s.auth.token);
  const [exporting, setExporting] = useState(false);
  const runExport = async (url: string, label: string) => {
    setExporting(true);
    const status = await downloadTrainingExport(url, token);
    setExporting(false);
    if (status === 0) toast.error('Network error while exporting. Please try again.');
    else if (status >= 400) toast.error(`Could not export ${label} (HTTP ${status}).`);
  };

  return (
    <>
      <EntityListPage
        title="Training providers"
        subtitle={`${total} ${total === 1 ? 'provider' : 'providers'} on file`}
        addLabel="Add provider"
        onAdd={canCreate ? crud.openCreate : undefined}
        actions={
          <>
            <Button
              variant="ghost"
              disabled={exporting}
              onClick={() => runExport(trainingProvidersCsvUrl(), 'CSV')}
            >
              <Download className="h-4 w-4" /> CSV
            </Button>
            <Button
              variant="ghost"
              disabled={exporting}
              onClick={() => runExport(trainingProvidersXlsxUrl(), 'XLSX')}
            >
              <Download className="h-4 w-4" /> XLSX
            </Button>
          </>
        }
        filters={<TrainingProvidersFilters search={search} onSearch={setSearch} />}
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load training providers"
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
        <TrainingProvidersTable
          providers={rows}
          isMutating={isMutating}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
        />
      </EntityListPage>

      <TrainingProviderFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}

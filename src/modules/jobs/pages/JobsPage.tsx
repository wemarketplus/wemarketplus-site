import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { toast } from 'sonner';
import { useUpdateJobMutation } from '../api/jobsApi';
import { JobsFilters } from '../components/JobsFilters';
import { JobsTable } from '../components/JobsTable';
import { useJobsList } from '../hooks/useJobsList';
import type { JobRecord, JobStatus } from '../types/jobsTypes';

/**
 * Field work queued against pipelines. Rows with a bot marker were spawned
 * automatically by a pipeline stage transition.
 */
export function JobsPage() {
  const {
    jobs,
    total,
    isLoading,
    isError,
    statusFilter,
    typeFilter,
    setStatusFilter,
    setTypeFilter,
  } = useJobsList();
  const [update, { isLoading: isSaving }] = useUpdateJobMutation();

  const changeStatus = async (job: JobRecord, status: JobStatus) => {
    if (status === job.status) return;
    try {
      await update({ id: job.id, patch: { status } }).unwrap();
      toast.success('Job updated.');
    } catch {
      toast.error('Could not update that job.');
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Jobs</h1>
        <p className="text-sm text-muted">
          {total} units of work across your pipelines
        </p>
      </header>

      <JobsFilters
        statusFilter={statusFilter}
        typeFilter={typeFilter}
        onStatus={setStatusFilter}
        onType={setTypeFilter}
      />

      {isError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          Could not load jobs.
        </p>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-soft">Loading jobs…</p>
      ) : (
        <JobsTable
          items={jobs}
          isBusy={isSaving}
          onStatusChange={(job, status) => void changeStatus(job, status)}
        />
      )}
    </div>
  );
}

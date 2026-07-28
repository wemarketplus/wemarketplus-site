import { useMemo } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { useListJobsQuery } from '../api/jobsApi';
import { setJobStatusFilter, setJobTypeFilter } from '../store/jobsSlice';
import type { JobStatus, JobType } from '../types/jobsTypes';

/**
 * Jobs list. Filters are applied server-side. `pipelineId` narrows the list to one
 * opportunity, which is how the pipeline detail view reuses this hook.
 */
export function useJobsList(pipelineId?: string) {
  const dispatch = useAppDispatch();
  const statusFilter = useAppSelector((s) => s.jobs.statusFilter);
  const typeFilter = useAppSelector((s) => s.jobs.typeFilter);

  const query = useMemo(
    () => ({
      pipelineId,
      status: statusFilter === 'all' ? undefined : statusFilter,
      jobType: typeFilter === 'all' ? undefined : typeFilter,
    }),
    [pipelineId, statusFilter, typeFilter],
  );

  const { data, isLoading, isFetching, isError } = useListJobsQuery(query);

  return {
    jobs: data?.data ?? [],
    total: data?.total ?? 0,
    isLoading,
    isFetching,
    isError,
    statusFilter,
    typeFilter,
    setStatusFilter: (value: JobStatus | 'all') =>
      dispatch(setJobStatusFilter(value)),
    setTypeFilter: (value: JobType | 'all') => dispatch(setJobTypeFilter(value)),
  };
}

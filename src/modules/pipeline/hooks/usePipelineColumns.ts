import { useMemo } from 'react';
import { PROSPECTS_FIXTURE } from '@/shared/fixtures';
import { useListProspectsQuery } from '@/modules/prospects';
import { PIPELINE_COLUMNS } from '../constants/pipelineConstants';
import { groupProspectsByStatus } from '../utils/pipelineUtils';

export function usePipelineColumns() {
  const { data } = useListProspectsQuery({});
  const prospects = data?.data ?? PROSPECTS_FIXTURE;
  const groups = useMemo(() => groupProspectsByStatus(prospects), [prospects]);

  return {
    columns: PIPELINE_COLUMNS.map((c) => ({
      ...c,
      items: groups[c.status] ?? [],
    })),
    total: prospects.length,
    isUsingFixture: !data,
  };
}

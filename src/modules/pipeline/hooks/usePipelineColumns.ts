import { useMemo } from 'react';
import { useListProspectsQuery, mapProspectRecord } from '@/modules/prospects';
import { PIPELINE_COLUMNS } from '../constants/pipelineConstants';
import { groupProspectsByStatus } from '../utils/pipelineUtils';

export function usePipelineColumns() {
  const { data } = useListProspectsQuery();
  const prospects = useMemo(
    () => (data ? data.data.map(mapProspectRecord) : []),
    [data],
  );
  const groups = useMemo(() => groupProspectsByStatus(prospects), [prospects]);

  return {
    columns: PIPELINE_COLUMNS.map((c) => ({
      ...c,
      items: groups[c.status] ?? [],
    })),
    total: prospects.length,
    isUsingFixture: false,
  };
}

import { useCallback } from 'react';
import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { prospectsApi } from '@/modules/prospects/api/prospectsApi';
import type { ProspectPipelineType } from '@/modules/prospects/types/prospectsTypes';
import type { ID } from '@/shared/types';
import {
  useGetPipelineBoardQuery,
  useMovePipelineStageMutation,
} from '../api/pipelineApi';
import { setDragging, setPipelineType } from '../store/pipelineSlice';
import type { ProspectStage } from '../types/pipelineTypes';

/**
 * The Kanban board. Reads the stage-grouped board from the backend and moves cards
 * through POST /pipeline/move — replacing the previous client-side grouping over
 * `/prospects`, which had no way to persist a stage change.
 */
export function usePipelineBoard() {
  const dispatch = useAppDispatch();
  const pipelineType = useAppSelector((s) => s.pipeline.pipelineType);
  const draggingProspectId = useAppSelector(
    (s) => s.pipeline.draggingProspectId,
  );

  const { data, isLoading, isFetching, isError } = useGetPipelineBoardQuery({
    pipelineType,
  });
  const [move, { isLoading: isMoving }] = useMovePipelineStageMutation();

  const changePipelineType = useCallback(
    (next: ProspectPipelineType) => dispatch(setPipelineType(next)),
    [dispatch],
  );

  const beginDrag = useCallback(
    (id: ID) => dispatch(setDragging(id)),
    [dispatch],
  );

  const endDrag = useCallback(() => dispatch(setDragging(null)), [dispatch]);

  const moveToStage = useCallback(
    async (prospectId: ID, toStage: ProspectStage) => {
      try {
        const result = await move({ prospectId, toStage }).unwrap();
        // The prospects list caches the pre-move stage; drop it so the list screen
        // and the board never disagree.
        dispatch(prospectsApi.util.invalidateTags([
          { type: 'Prospects.List', id: 'PARTIAL-LIST' },
        ]));
        // Surface the stage-triggered job so the automation is visible, not silent.
        toast.success(
          result.spawnedJob
            ? `Moved to ${toStage.replace(/_/g, ' ')} · job created: ${
                result.spawnedJob.objective ?? result.spawnedJob.jobType
              }`
            : `Moved to ${toStage.replace(/_/g, ' ')}`,
        );
        return true;
      } catch {
        toast.error('Could not move that card. Please try again.');
        return false;
      } finally {
        dispatch(setDragging(null));
      }
    },
    [dispatch, move],
  );

  const columns = data?.columns ?? [];
  const total = columns.reduce((sum, column) => sum + column.total, 0);

  return {
    pipelineType,
    changePipelineType,
    columns,
    unstaged: data?.unstaged ?? [],
    total,
    isLoading,
    isFetching,
    isError,
    isMoving,
    draggingProspectId,
    beginDrag,
    endDrag,
    moveToStage,
  };
}

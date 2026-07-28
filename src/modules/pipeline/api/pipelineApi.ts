import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import { PROSPECTS_TAGS } from '@/modules/prospects/constants/prospectsConstants';
import type { ApiEnvelope } from '@/shared/types';
import { PIPELINE_TAGS } from '../constants/pipelineConstants';
import type {
  MovePipelineStageRequest,
  MovePipelineStageResult,
  PipelineBoard,
  PipelineBoardQuery,
} from '../types/pipelineTypes';

// Verified against wemarketplus-backend/src/pipeline/pipeline.controller.ts:
//   GET  /pipeline/board?pipelineType -> PipelineBoardResponseDto
//   POST /pipeline/move  body:MovePipelineStageDto -> MovePipelineStageResponseDto
//
// The board is served stage-grouped by the backend (columns + labels + cards), so the
// column vocabulary can never drift from the backend stage enum.
export const pipelineApi = createApi({
  reducerPath: 'pipelineApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [PIPELINE_TAGS.Board],
  endpoints: (build) => ({
    getPipelineBoard: build.query<PipelineBoard, PipelineBoardQuery | void>({
      query: (params) => ({ url: '/pipeline/board', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PipelineBoard>) => res.data,
      providesTags: [{ type: PIPELINE_TAGS.Board, id: 'CURRENT' }],
    }),
    movePipelineStage: build.mutation<
      MovePipelineStageResult,
      MovePipelineStageRequest
    >({
      query: (body) => ({ url: '/pipeline/move', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<MovePipelineStageResult>) => res.data,
      // Invalidate the board so the moved card lands in its new column.
      invalidatesTags: [{ type: PIPELINE_TAGS.Board, id: 'CURRENT' }],
    }),
  }),
});

/**
 * Tags the prospects list must drop after a stage move, so the Prospects screen
 * does not keep showing the pre-move stage. Applied by the move hook via dispatch
 * rather than declared here, because the two APIs have separate tag registries.
 */
export const PROSPECT_TAGS_INVALIDATED_BY_MOVE = [
  { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
] as const;

export const { useGetPipelineBoardQuery, useMovePipelineStageMutation } =
  pipelineApi;

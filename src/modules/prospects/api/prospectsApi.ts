import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { PROSPECTS_TAGS } from '../constants/prospectsConstants';
import type {
  CreateProspectRequest,
  ListProspectsQuery,
  PatientContextRecord,
  PatientDirectoryEntry,
  ProspectRecord,
  UpdateProspectRequest,
  ReengagementRow,
} from '../types/prospectsTypes';

// Verified against wemarketplus-backend/src/prospects/prospects.controller.ts:
//   GET    /prospects?page&limit&stage&assignedTo -> PaginatedResult<ProspectResponseDto>
//   GET    /prospects/patient-directory            -> MyPatientResponseDto[]  (field roles)
//   GET    /prospects/:id
//   POST   /prospects                              body:CreateProspectDto
//   PATCH  /prospects/:id                          body:UpdateProspectDto
//   DELETE /prospects/:id                          (admin/owner/manager only)
export const prospectsApi = createApi({
  reducerPath: 'prospectsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [PROSPECTS_TAGS.List, PROSPECTS_TAGS.Detail],
  endpoints: (build) => ({
    listProspects: build.query<PaginatedPayload<ProspectRecord>, ListProspectsQuery | void>({
      query: (params) => ({ url: '/prospects', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<ProspectRecord>>) => res.data,
      providesTags: (result) =>
        result
          ? [
              ...result.data.map((p) => ({ type: PROSPECTS_TAGS.Detail, id: p.id }) as const),
              { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
            ]
          : [{ type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    /**
     * The re-engagement queue: open pipeline rows quiet past the 30-day
     * threshold, longest-quiet first. Inactivity is derived server-side from
     * notes, completed visits, completed jobs and stage changes — never from
     * `updatedAt`, which any field edit would reset.
     */
    listReengagement: build.query<
      ReengagementRow[],
      { limit?: number; assignedTo?: string } | void
    >({
      query: (params) => ({
        url: '/prospects/re-engagement',
        params: params ?? undefined,
      }),
      transformResponse: (res: ApiEnvelope<ReengagementRow[]>) => res.data,
      providesTags: [{ type: PROSPECTS_TAGS.List, id: 'REENGAGEMENT' }],
    }),
    /**
     * The patient directory: every patient in the tenant as {id, name, stage}.
     *
     * The ONE prospects route the clinical roles may call — Nurse and Caregiver are
     * 403 on `listProspects` above. It exists so a clinician can always name the
     * patient they are logging a family conversation about, which the compliance
     * rule ("log it every time, even a quick call") requires and the caller's own
     * visit list could not deliver.
     *
     * Tagged into the prospects List tag so creating or deleting a patient refreshes
     * the pickers built from it.
     */
    getPatientDirectory: build.query<PatientDirectoryEntry[], void>({
      query: () => ({ url: '/prospects/patient-directory' }),
      transformResponse: (res: ApiEnvelope<PatientDirectoryEntry[]>) => res.data,
      providesTags: [{ type: PROSPECTS_TAGS.List, id: 'PATIENT-DIRECTORY' }],
    }),
    /**
     * Who referred ONE patient, and the contact on that referral. The other
     * prospects route the clinical roles may call.
     *
     * It exists because the note form showed a clinician a Referral source and a
     * Contact picker that could never populate — both list endpoints are
     * marketing-only. This returns just those two names for the patient already
     * selected, which the form renders read-only.
     */
    getPatientContext: build.query<PatientContextRecord, string>({
      query: (id) => ({ url: `/prospects/${id}/patient-context` }),
      transformResponse: (res: ApiEnvelope<PatientContextRecord>) => res.data,
      providesTags: (_r, _e, id) => [{ type: PROSPECTS_TAGS.Detail, id }],
    }),
    getProspect: build.query<ProspectRecord, string>({
      query: (id) => ({ url: `/prospects/${id}` }),
      transformResponse: (res: ApiEnvelope<ProspectRecord>) => res.data,
      providesTags: (_r, _e, id) => [{ type: PROSPECTS_TAGS.Detail, id }],
    }),
    createProspect: build.mutation<ProspectRecord, CreateProspectRequest>({
      query: (body) => ({ url: '/prospects', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<ProspectRecord>) => res.data,
      invalidatesTags: [
        { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
        // A new patient must appear in the clinicians' picker without a reload —
        // the admission that created them is usually why a nurse is about to ring
        // the family.
        { type: PROSPECTS_TAGS.List, id: 'PATIENT-DIRECTORY' },
      ],
    }),
    updateProspect: build.mutation<ProspectRecord, { id: string; patch: UpdateProspectRequest }>({
      query: ({ id, patch }) => ({ url: `/prospects/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<ProspectRecord>) => res.data,
      invalidatesTags: (_r, _e, { id }) => [
        { type: PROSPECTS_TAGS.Detail, id },
        { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
        // An edit can rename the patient, and the directory is a list of names.
        { type: PROSPECTS_TAGS.List, id: 'PATIENT-DIRECTORY' },
      ],
    }),
    deleteProspect: build.mutation<void, string>({
      query: (id) => ({ url: `/prospects/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [
        { type: PROSPECTS_TAGS.Detail, id },
        { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
        { type: PROSPECTS_TAGS.List, id: 'PATIENT-DIRECTORY' },
      ],
    }),
  }),
});

export const {
  useListReengagementQuery,
  useListProspectsQuery,
  useGetPatientDirectoryQuery,
  useGetPatientContextQuery,
  useGetProspectQuery,
  useCreateProspectMutation,
  useUpdateProspectMutation,
  useDeleteProspectMutation,
} = prospectsApi;

import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, ID, PaginatedPayload, PaginationParams } from '@/shared/types';

// The HospiceLink contact record (hl_contacts) — the referring PERSON that Prospects
// and Jobs point at, created automatically during lead conversion.
//
// Verified against wemarketplus-backend/src/hospice-contacts/hospice-contacts.controller.ts:
//   GET    /hl/contacts?page&limit&search&contactType&companyId&ownerId
//   GET    /hl/contacts/:id
//   POST   /hl/contacts
//   PATCH  /hl/contacts/:id
//   DELETE /hl/contacts/:id   (admin/owner/manager only)
// NOTE the route prefix is `hl/contacts`, NOT `hospice-contacts` — the module is
// named for the entity, the route is namespaced under the product.
//
// THIS WAS READ-ONLY ON PURPOSE UNTIL NOW. The audit recorded this module as
// API-ONLY — complete backend, no screen, no nav entry — and giving it a screen was
// open decision item 1. That decision is taken: the record now has its own screen,
// and Grants-side `contacts` is left completely alone (separate table, different
// field set, un-gated cross-product). The two are NOT merged, which the document
// explicitly rules out.
export type HospiceContactType =
  | 'referral_source'
  | 'patient'
  | 'family_caregiver'
  | 'poa';

export type HospiceContactRoleTitle =
  | 'discharge_planner'
  | 'case_manager'
  | 'physician'
  | 'social_worker'
  | 'nurse'
  | 'admin';

export type HospiceContactPreferredMethod = 'call' | 'text' | 'email' | 'fax';

export interface HospiceContactRecord {
  id: ID;
  tenantId: ID;
  firstName: string;
  lastName: string;
  /** Server-composed convenience field. */
  fullName: string;
  contactType: HospiceContactType;
  roleTitle: HospiceContactRoleTitle | null;
  companyId: ID | null;
  phone: string | null;
  mobile: string | null;
  email: string | null;
  fax: string | null;
  preferredMethod: HospiceContactPreferredMethod | null;
  npi: string | null;
  specialty: string | null;
  /** Enforced server-side: a DNC contact is refused as an appointment attendee. */
  doNotContact: boolean;
  ownerId: ID | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateHospiceContactRequest {
  firstName: string;
  lastName: string;
  contactType?: HospiceContactType;
  /**
   * `null` as well as `undefined`, and that is the fix for a real defect.
   *
   * This and `preferredMethod` are nullable enum columns, and the API distinguishes
   * an OMITTED key ("leave it alone") from an explicit `null` ("clear it"). While
   * the type could only say `undefined`, a user who picked the blank option to
   * clear a role they had set earlier produced a request with the key absent —
   * which the server correctly read as "leave it alone", so the old value silently
   * stayed put and the change appeared to save.
   *
   * The server already supported clearing: its update merges any key that is
   * PRESENT, including null, and skips only `undefined`. Nothing changed there.
   * What was missing was a client type that could express `null` at all.
   *
   * Not `''`: both columns are Postgres ENUMS, so an empty string is not a member
   * and would fail `@IsEnum` before reaching the database. `null` is the only way
   * to say "no value" for these two — which is also why they are the only two
   * fields here that send null rather than being omitted when blank.
   */
  roleTitle?: HospiceContactRoleTitle | null;
  companyId?: string;
  phone?: string;
  mobile?: string;
  email?: string;
  fax?: string;
  /** See `roleTitle` — same nullable enum column, same reason. */
  preferredMethod?: HospiceContactPreferredMethod | null;
  npi?: string;
  specialty?: string;
  doNotContact?: boolean;
  notes?: string;
}

export type UpdateHospiceContactRequest = Partial<CreateHospiceContactRequest>;

export interface ListHospiceContactsQuery extends PaginationParams {
  search?: string;
  contactType?: HospiceContactType;
  companyId?: string;
  ownerId?: string;
}

const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const hospiceContactsApi = createApi({
  reducerPath: 'hospiceContactsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['HospiceContact'],
  endpoints: (build) => ({
    listHospiceContacts: build.query<
      PaginatedPayload<HospiceContactRecord>,
      ListHospiceContactsQuery | void
    >({
      query: (params) => ({ url: '/hl/contacts', params: params ?? undefined }),
      transformResponse: list<HospiceContactRecord>,
      providesTags: ['HospiceContact'],
    }),

    getHospiceContact: build.query<HospiceContactRecord, string>({
      query: (id) => ({ url: `/hl/contacts/${id}` }),
      transformResponse: env<HospiceContactRecord>,
      providesTags: ['HospiceContact'],
    }),

    createHospiceContact: build.mutation<
      HospiceContactRecord,
      CreateHospiceContactRequest
    >({
      query: (body) => ({ url: '/hl/contacts', method: 'POST', body }),
      transformResponse: env<HospiceContactRecord>,
      invalidatesTags: ['HospiceContact'],
    }),

    updateHospiceContact: build.mutation<
      HospiceContactRecord,
      { id: string; patch: UpdateHospiceContactRequest }
    >({
      query: ({ id, patch }) => ({
        url: `/hl/contacts/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<HospiceContactRecord>,
      invalidatesTags: ['HospiceContact'],
    }),

    deleteHospiceContact: build.mutation<void, string>({
      query: (id) => ({ url: `/hl/contacts/${id}`, method: 'DELETE' }),
      invalidatesTags: ['HospiceContact'],
    }),
  }),
});

export const {
  useListHospiceContactsQuery,
  useGetHospiceContactQuery,
  useCreateHospiceContactMutation,
  useUpdateHospiceContactMutation,
  useDeleteHospiceContactMutation,
} = hospiceContactsApi;

/** Display name for a picker option. Falls back gracefully on partial records. */
export const hospiceContactLabel = (c: HospiceContactRecord): string => {
  const name = [c.firstName, c.lastName].filter(Boolean).join(' ').trim();
  const qualifier = c.roleTitle?.replace(/_/g, ' ');
  return qualifier ? `${name || 'Unnamed contact'} — ${qualifier}` : name || 'Unnamed contact';
};

export const CONTACT_TYPE_LABELS: Record<HospiceContactType, string> = {
  referral_source: 'Referral source',
  patient: 'Patient',
  family_caregiver: 'Family / caregiver',
  poa: 'Power of attorney',
};

export const ROLE_TITLE_LABELS: Record<HospiceContactRoleTitle, string> = {
  discharge_planner: 'Discharge planner',
  case_manager: 'Case manager',
  physician: 'Physician',
  social_worker: 'Social worker',
  nurse: 'Nurse',
  admin: 'Admin',
};

export const PREFERRED_METHOD_LABELS: Record<
  HospiceContactPreferredMethod,
  string
> = {
  call: 'Call',
  text: 'Text',
  email: 'Email',
  fax: 'Fax',
};

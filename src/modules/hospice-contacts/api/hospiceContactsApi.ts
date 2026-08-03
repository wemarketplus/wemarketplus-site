import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, ID, PaginatedPayload, PaginationParams } from '@/shared/types';

// Read access to the HospiceLink contact record (hl_contacts) — the referring
// PERSON created during lead conversion, which Prospects and Jobs point at.
//
// Verified against wemarketplus-backend/src/hospice-contacts/hospice-contacts.controller.ts:
//   GET /hl/contacts?page&limit -> PaginatedResult<HospiceContactResponseDto>
// NOTE the route prefix is `hl/contacts`, NOT `hospice-contacts` — the module is
// named for the entity, the route is namespaced under the product.
//
// Deliberately read-only and deliberately minimal. The audit found this module is
// API-ONLY: complete backend, no screen, no nav entry (AUDIT-HOSPICELINK.md row
// 13), and giving it a full screen is open decision item 1. This slice exists so
// record-reference pickers can OFFER contacts by name instead of asking a user to
// paste a UUID — it is not the screen that decision covers, and it should not grow
// into one without that sign-off.
export interface HospiceContactRecord {
  id: ID;
  tenantId: ID;
  firstName: string;
  lastName: string;
  contactType: string;
  roleTitle: string | null;
  companyId: ID | null;
  email: string | null;
  phone: string | null;
  specialty: string | null;
  doNotContact: boolean;
}

export const hospiceContactsApi = createApi({
  reducerPath: 'hospiceContactsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['HospiceContact'],
  endpoints: (build) => ({
    listHospiceContacts: build.query<
      PaginatedPayload<HospiceContactRecord>,
      PaginationParams | void
    >({
      query: (params) => ({ url: '/hl/contacts', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<HospiceContactRecord>>) =>
        res.data,
      providesTags: ['HospiceContact'],
    }),
  }),
});

export const { useListHospiceContactsQuery } = hospiceContactsApi;

/** Display name for a picker option. Falls back gracefully on partial records. */
export const hospiceContactLabel = (c: HospiceContactRecord): string => {
  const name = [c.firstName, c.lastName].filter(Boolean).join(' ').trim();
  const qualifier = c.roleTitle?.replace(/_/g, ' ');
  return qualifier ? `${name || 'Unnamed contact'} — ${qualifier}` : name || 'Unnamed contact';
};

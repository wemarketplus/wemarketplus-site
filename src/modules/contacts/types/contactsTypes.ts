import type { ID, ISODateString, PaginationParams } from '@/shared/types';

// Mirrors wemarketplus-backend/src/contacts/dto/contact-response.dto.ts.
// Contacts are polymorphic — they attach to any record via recordType/recordId.
export interface ContactRecord {
  id: ID;
  tenantId: ID;
  name: string;
  title: string | null;
  email: string | null;
  phone: string | null;
  recordType: string | null;
  recordId: ID | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// Every field but `name` maps to a nullable column and is sent as an explicit
// `null` to clear it — an omitted key in a PATCH means "leave unchanged".
export interface CreateContactRequest {
  name: string;
  title?: string | null;
  email?: string | null;
  phone?: string | null;
  recordType?: string | null;
  recordId?: string | null;
  notes?: string | null;
}

export type UpdateContactRequest = Partial<CreateContactRequest>;

export interface ListContactsQuery extends PaginationParams {
  recordType?: string;
  recordId?: string;
}

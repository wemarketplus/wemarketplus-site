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

export interface CreateContactRequest {
  name: string;
  title?: string;
  email?: string;
  phone?: string;
  recordType?: string;
  recordId?: string;
  notes?: string;
}

export type UpdateContactRequest = Partial<CreateContactRequest>;

export interface ListContactsQuery extends PaginationParams {
  recordType?: string;
  recordId?: string;
}

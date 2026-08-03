import type { EntityField } from '@/shared/ui/entity';
import type { ContactFormValues } from '../schema/contactSchema';

export const CONTACTS_PAGE_SIZE = 20;

// Field descriptors driving the create/edit modal (EntityFormModal). Order here
// is render order; `full` spans both grid columns. recordType/recordId let a
// contact attach to any polymorphic record; they're free-text/UUID for now.
export const CONTACT_FIELDS: ReadonlyArray<EntityField<ContactFormValues>> = [
  { name: 'name', label: 'Name', full: true, placeholder: 'Jane Doe' },
  { name: 'title', label: 'Title', placeholder: 'Program Director' },
  { name: 'email', label: 'Email', type: 'email', placeholder: 'jane@example.org' },
  { name: 'phone', label: 'Phone', type: 'tel', placeholder: '(555) 123-4567' },
  { name: 'recordType', label: 'Record type', placeholder: 'company, grant…' },
  // THE ONE REMAINING RAW-ID FIELD, and deliberately so.
  //
  // A Grants contact is POLYMORPHIC: it attaches to any record via
  // (recordType, recordId) — see contactsTypes.ts. `recordType` is free text with
  // no enum behind it, so there is no list to drive a picker from and no way to
  // know WHICH entity's ids to offer. Making this usable needs a product answer
  // first — which record types may a contact attach to? — and then a dependent
  // picker (pick the type, then pick from that type's list).
  //
  // Every other record reference in this app is now `type: 'lookup'`. Do not copy
  // this field as a pattern; it is an open gap, not a precedent.
  { name: 'recordId', label: 'Record id (UUID)', placeholder: 'optional' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];

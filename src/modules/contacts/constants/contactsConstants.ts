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
  { name: 'recordId', label: 'Record id (UUID)', placeholder: 'optional' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];

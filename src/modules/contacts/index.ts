// Grant-CRM contacts — polymorphic contacts (attach to any record). Full CRUD
// UI built on the shared entity kit (@/shared/ui/entity). See ContactsPage for
// the reference usage other modules clone.
export { ContactsPage } from './pages/ContactsPage';
export {
  contactsApi,
  useListContactsQuery,
  useGetContactQuery,
  useCreateContactMutation,
  useUpdateContactMutation,
  useDeleteContactMutation,
} from './api/contactsApi';
export type {
  ContactRecord,
  CreateContactRequest,
  UpdateContactRequest,
  ListContactsQuery,
} from './types/contactsTypes';

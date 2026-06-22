// Grant-CRM contacts — API-only module (no page UI yet).
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

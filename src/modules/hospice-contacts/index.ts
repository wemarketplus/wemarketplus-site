// The HospiceLink contact record (hl_contacts). Separate table from the Grants-side
// `contacts` module by design — the field sets are disjoint and merging them is
// explicitly ruled out by the module-flow document.
export { HospiceContactsPage } from './pages/HospiceContactsPage';
export {
  hospiceContactsApi,
  hospiceContactLabel,
  useListHospiceContactsQuery,
  useGetHospiceContactQuery,
  useCreateHospiceContactMutation,
  useUpdateHospiceContactMutation,
  useDeleteHospiceContactMutation,
  CONTACT_TYPE_LABELS,
  ROLE_TITLE_LABELS,
  PREFERRED_METHOD_LABELS,
} from './api/hospiceContactsApi';
export type {
  HospiceContactRecord,
  HospiceContactType,
  HospiceContactRoleTitle,
  HospiceContactPreferredMethod,
  CreateHospiceContactRequest,
  UpdateHospiceContactRequest,
  ListHospiceContactsQuery,
} from './api/hospiceContactsApi';

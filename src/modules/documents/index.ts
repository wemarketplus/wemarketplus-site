// Grant-CRM documents (employer + WIB) — API-only module (no page UI yet).
export {
  documentsApi,
  useListEmployerDocumentsQuery,
  useCreateEmployerDocumentMutation,
  useDeleteEmployerDocumentMutation,
  useListWibDocumentsQuery,
  useCreateWibDocumentMutation,
  useDeleteWibDocumentMutation,
} from './api/documentsApi';
export type {
  DocumentRecord,
  CreateDocumentRequest,
  ListDocumentsQuery,
} from './types/documentsTypes';

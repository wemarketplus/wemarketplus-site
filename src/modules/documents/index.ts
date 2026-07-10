// Grant-CRM documents (employer + WIB) — parent-scoped list + record-metadata
// create + delete UI (no binary upload in this phase).
export { DocumentsPage } from './pages/DocumentsPage';
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
export {
  DOCUMENT_SCOPE,
  DOCUMENT_SCOPE_LABELS,
  type DocumentScope,
} from './constants/documentsConstants';

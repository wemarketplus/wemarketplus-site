// Company-scoped document metadata — list + record + delete (no binary upload in
// this phase).
export { DocumentsPage } from './pages/DocumentsPage';
export {
  documentsApi,
  useListEmployerDocumentsQuery,
  useCreateEmployerDocumentMutation,
  useDeleteEmployerDocumentMutation,
} from './api/documentsApi';
export type {
  DocumentRecord,
  CreateDocumentRequest,
  ListDocumentsQuery,
} from './types/documentsTypes';

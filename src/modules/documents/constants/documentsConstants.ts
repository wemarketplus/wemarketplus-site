import type { EntityField } from '@/shared/ui/entity';
import type { DocumentFormValues } from '../schema/documentSchema';

export const DOCUMENTS_PAGE_SIZE = 20;

// Documents are scoped to a parent company. The backend also has a parallel
// WIB-scoped document store (/wib-documents), which is a Grants-domain concept
// deliberately NOT surfaced here — see the note in documentsApi.ts.
//
// There is no "list all documents" endpoint, so the page picks a company first.

// Field descriptors driving the "record document" create modal (metadata only —
// this phase does NOT upload a binary; driveUrl references an existing file).
export const DOCUMENT_FIELDS: ReadonlyArray<EntityField<DocumentFormValues>> = [
  { name: 'fileName', label: 'File name', full: true, placeholder: 'W-9 form.pdf' },
  { name: 'driveUrl', label: 'Drive URL', full: true, placeholder: 'https://drive.google.com/…' },
  { name: 'documentType', label: 'Document type', placeholder: 'tax, contract…' },
  { name: 'mimeType', label: 'MIME type', placeholder: 'application/pdf' },
  { name: 'fileId', label: 'File id', placeholder: 'optional Drive file id' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];

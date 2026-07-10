import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { DocumentFormValues } from '../schema/documentSchema';

export const DOCUMENTS_PAGE_SIZE = 20;

// The backend has two parallel document stores, each scoped to a different parent
// and each REQUIRING that parent's id on the list/create call. There is no
// "list all documents" endpoint, so the page picks a scope + parent id first.
export const DOCUMENT_SCOPE = {
  Employer: 'employer',
  Wib: 'wib',
} as const;
export type DocumentScope = (typeof DOCUMENT_SCOPE)[keyof typeof DOCUMENT_SCOPE];

export const DOCUMENT_SCOPE_LABELS: Record<DocumentScope, string> = {
  employer: 'Employer (company)',
  wib: 'WIB',
};

// Label for the parent-id input, per scope.
export const DOCUMENT_PARENT_LABELS: Record<DocumentScope, string> = {
  employer: 'Company id (UUID)',
  wib: 'WIB id (UUID)',
};

export const DOCUMENT_SCOPE_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  ...Object.values(DOCUMENT_SCOPE).map((v) => ({ value: v, label: DOCUMENT_SCOPE_LABELS[v] })),
];

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

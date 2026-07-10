import { opt } from '@/shared/ui/entity';
import type { CreateDocumentRequest } from '../types/documentsTypes';
import type { DocumentFormValues } from '../schema/documentSchema';

// Form values -> POST body. fileName/driveUrl are required; the rest are dropped
// when blank so the service applies its legacy defaults (mimeType/documentType).
export function toCreateDocument(values: DocumentFormValues): CreateDocumentRequest {
  return {
    fileName: values.fileName.trim(),
    driveUrl: values.driveUrl.trim(),
    ...opt('fileId', values.fileId),
    ...opt('mimeType', values.mimeType),
    ...opt('documentType', values.documentType),
    ...opt('notes', values.notes),
  };
}

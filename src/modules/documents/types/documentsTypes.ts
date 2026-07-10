import type { ID, ISODateString } from '@/shared/types';

// Mirrors wemarketplus-backend/src/documents/dto/document-response.dto.ts.
// Used for both employer-documents and wib-documents (same shape).
export interface DocumentRecord {
  id: ID;
  tenantId: ID;
  parentId: ID;
  fileId: string | null;
  fileName: string;
  mimeType: string;
  driveUrl: string;
  documentType: string;
  notes: string | null;
  uploadedBy: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateDocumentRequest {
  fileName: string;
  driveUrl: string;
  fileId?: string;
  mimeType?: string;
  documentType?: string;
  notes?: string;
}

export interface ListDocumentsQuery {
  page?: number;
  limit?: number;
  documentType?: string;
}

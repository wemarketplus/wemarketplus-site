import { z } from 'zod';

// "Record document" metadata form — mirrors CreateDocumentDto
// (wemarketplus-backend/src/documents/dto/create-document.dto.ts). `fileName` and
// `driveUrl` are required; mimeType/documentType default in the service. No binary
// upload in this phase — driveUrl references an existing file.
export const documentSchema = z.object({
  fileName: z.string().min(1, 'File name is required').max(255),
  driveUrl: z.string().min(1, 'Drive URL is required').url('Enter a valid URL').max(2048),
  fileId: z.string().max(255).optional(),
  mimeType: z.string().max(255).optional(),
  documentType: z.string().max(255).optional(),
  notes: z.string().optional(),
});

export type DocumentFormValues = z.infer<typeof documentSchema>;

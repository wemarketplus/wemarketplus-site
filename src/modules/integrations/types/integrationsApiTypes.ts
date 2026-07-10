import type { ID, ISODateString } from '@/shared/types';

// Backend integration record shapes — wemarketplus-backend/src/integrations (drive).
export interface DriveStatus {
  connected: boolean;
  expiryDate?: ISODateString | null;
}

export interface DriveFile {
  id: ID;
  name: string;
  mimeType: string;
  modifiedTime?: ISODateString;
  webViewLink?: string;
}

export interface ListDriveFilesQuery {
  folderId?: string;
  mime?: string;
}

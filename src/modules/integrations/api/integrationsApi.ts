import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { DriveFile, DriveStatus, ListDriveFilesQuery } from '../types/integrationsApiTypes';

// Backend integrations — wemarketplus-backend/src/integrations.
//   GET    /drive/status            -> { connected, expiryDate? }
//   GET    /drive/files?folderId&mime -> DriveFile[]
//   DELETE /drive/files/:fileId
//   GET    /auth/google             -> Google OAuth start (see utils/googleOAuthUrl)
// Aircall + Google OAuth callback are server-to-server webhooks/redirects, not
// client RTK Query calls. The integration tile catalog on the page stays as a
// fixture; this slice surfaces the one live, mappable resource (Drive status).
export const integrationsApi = createApi({
  reducerPath: 'integrationsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['DriveStatus', 'DriveFiles'],
  endpoints: (build) => ({
    getDriveStatus: build.query<DriveStatus, void>({
      query: () => ({ url: '/drive/status' }),
      transformResponse: (res: ApiEnvelope<DriveStatus>) => res.data,
      providesTags: ['DriveStatus'],
    }),
    listDriveFiles: build.query<DriveFile[], ListDriveFilesQuery | void>({
      query: (params) => ({ url: '/drive/files', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<DriveFile[]>) => res.data,
      providesTags: ['DriveFiles'],
    }),
    deleteDriveFile: build.mutation<void, string>({
      query: (fileId) => ({ url: `/drive/files/${fileId}`, method: 'DELETE' }),
      invalidatesTags: ['DriveFiles'],
    }),
  }),
});

export const {
  useGetDriveStatusQuery,
  useListDriveFilesQuery,
  useDeleteDriveFileMutation,
} = integrationsApi;

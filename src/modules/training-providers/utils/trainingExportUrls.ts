// CSV/XLSX exports are binary downloads, not RTK Query JSON calls — build the
// authenticated download URL for the browser to open directly.
const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

export const trainingProvidersCsvUrl = (): string => `${apiBase()}/training-providers/export/csv`;
export const trainingProvidersXlsxUrl = (): string => `${apiBase()}/training-providers/export/xlsx`;
export const rosterExportUrl = (applicationId: string): string =>
  `${apiBase()}/training-rosters/export/${applicationId}`;

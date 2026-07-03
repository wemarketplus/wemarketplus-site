// DSAR / tenant data export (GET /data-export/download) is an authenticated
// GET that streams a .json attachment, not an RTK Query JSON call — build the
// URL for downloadAuthenticated to fetch with the Bearer token.
const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

export const dataExportDownloadUrl = (): string => `${apiBase()}/data-export/download`;

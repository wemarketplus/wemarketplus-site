// Binary export / import-template downloads (not RTK Query JSON calls) — build
// the authenticated URL for the browser to open directly.
const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

export const exportCsvUrl = (type: string): string => `${apiBase()}/export/${type}`;
export const exportXlsxUrl = (type: string): string => `${apiBase()}/export/${type}/xlsx`;
export const importTemplateCsvUrl = (type: string): string => `${apiBase()}/template/${type}`;
export const importTemplateXlsxUrl = (type: string): string =>
  `${apiBase()}/import/template/${type}/xlsx`;

import { toast } from 'sonner';

export function useEvidenceExport() {
  const onExportJson = () => toast.message('Export JSON — backend pending');
  const onExportCsv = () => toast.message('Export CSV — backend pending');
  return { onExportJson, onExportCsv };
}

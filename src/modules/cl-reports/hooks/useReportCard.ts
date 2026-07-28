import { useState } from 'react';
import { toast } from 'sonner';
import { useAppSelector } from '@/app/hooks';
import { useActiveProduct } from '@/modules/access';
import { Product } from '@/shared/types';
import { downloadAuthenticated } from '@/modules/admin/utils/authenticatedDownload';
import type { ReportDefinition } from '../types/clReportsTypes';

const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

export function useReportCard(report: ReportDefinition) {
  const token = useAppSelector((s) => s.auth.token);
  const { activeProduct: product } = useActiveProduct();
  const [isRunning, setIsRunning] = useState(false);

  const onRun = async () => {
    // Non-CommunityLink products have no backend report export yet.
    if (product !== Product.CommunityLink) {
      toast.message(`${report.title} — export pending backend`);
      return;
    }
    setIsRunning(true);
    const url = `${apiBase()}/cl/reports/${report.id}/export.csv`;
    const status = await downloadAuthenticated(url, token);
    setIsRunning(false);
    if (status === 403) {
      toast.error('You do not have permission to export reports.');
    } else if (status === 401) {
      toast.error('Your session has expired. Sign in again.');
    } else if (status === 0 || status >= 400) {
      toast.error('Export failed. Try again.');
    } else {
      toast.success(`${report.title} exported`);
    }
  };

  return { onRun, isRunning };
}

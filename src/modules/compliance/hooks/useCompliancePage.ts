import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { setComplianceQuery } from '../store/complianceSlice';

export function useCompliancePage() {
  const dispatch = useAppDispatch();
  const query = useAppSelector((s) => s.compliance.query);
  const setQuery = (q: string) => dispatch(setComplianceQuery(q));
  const onExport = () => toast.message('Export — endpoint pending backend');
  return { query, setQuery, onExport };
}

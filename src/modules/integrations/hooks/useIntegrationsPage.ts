import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { setIntegrationCategory } from '../store/integrationsSlice';
import type { IntegrationsUiState } from '../types/integrationsTypes';

export function useIntegrationsPage() {
  const dispatch = useAppDispatch();
  const category = useAppSelector((s) => s.integrations.category);
  const setCategory = (c: IntegrationsUiState['category']) =>
    dispatch(setIntegrationCategory(c));
  return { category, setCategory };
}

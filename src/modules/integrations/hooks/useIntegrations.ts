import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { INTEGRATIONS_CATALOG } from '../constants/integrationsConstants';

export function useIntegrations() {
  const category = useAppSelector((s) => s.integrations.category);
  const filtered = useMemo(
    () =>
      category === 'all'
        ? INTEGRATIONS_CATALOG
        : INTEGRATIONS_CATALOG.filter((i) => i.category === category),
    [category],
  );
  return { integrations: filtered, total: INTEGRATIONS_CATALOG.length };
}

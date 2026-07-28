import { useMemo } from 'react';
import { useActiveProduct } from '@/modules/access';
import { Product } from '@/shared/types';
import { REPORT_CATALOG } from '../constants/clReportsConstants';
import { groupReportsByCategory } from '../utils/groupReports';
import { useListClReportsQuery } from '../api/clReportsApi';
import type { ClReportResult } from '../types/clReportsTypes';

// For CommunityLink tenants, report metrics come live from the backend
// (cl/reports). The static REPORT_CATALOG still supplies card metadata
// (title/description/category grouping); live metrics are overlaid by id.
// Non-CommunityLink products keep the previous fixture-only behavior. Keys off
// the ACTIVE product so a dual-product user gets live CL reports on the CL
// dashboard.
export function useReportCatalog() {
  const { activeProduct } = useActiveProduct();
  const isCommunityLink = activeProduct === Product.CommunityLink;

  const { data, isLoading, isFetching } = useListClReportsQuery(undefined, {
    skip: !isCommunityLink,
  });

  const metricsById = useMemo(() => {
    const map = new Map<string, ClReportResult>();
    for (const r of data ?? []) map.set(r.id, r);
    return map;
  }, [data]);

  return {
    reports: REPORT_CATALOG,
    grouped: groupReportsByCategory(REPORT_CATALOG),
    // True only for non-CL products (which still have no backend); CL is now
    // backed by cl/reports.
    isUsingFixture: !isCommunityLink,
    isBackendBacked: isCommunityLink,
    isLoading: isCommunityLink && isLoading,
    isFetching: isCommunityLink && isFetching,
    metricsById,
  };
}

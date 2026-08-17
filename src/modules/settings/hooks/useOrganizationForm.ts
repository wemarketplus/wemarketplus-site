import { useCallback, useMemo } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import {
  useGetMyTenantQuery,
  useUpdateMyTenantMutation,
} from '../api/settingsApi';
import { DEFAULT_REPORT_TIMEZONE } from '../constants/settingsConstants';
import type { OrganizationFormValues } from '../schema/organizationSchema';

// Loads the caller's own tenant profile (GET /tenants/me) and persists edits
// via PATCH /tenants/me. Keeps the Organization tab unaware of the tenants
// module contract — only this hook maps the DTO to/from the form shape.
export function useOrganizationForm() {
  const { data, isLoading, isError, refetch } = useGetMyTenantQuery();
  const [updateMyTenant, state] = useUpdateMyTenantMutation();

  const initialValues: OrganizationFormValues = useMemo(
    () => ({
      name: data?.name ?? '',
      address: data?.address ?? '',
      city: data?.city ?? '',
      state: data?.state ?? '',
      phone: data?.phone ?? '',
      reportTimezone: data?.reportTimezone ?? DEFAULT_REPORT_TIMEZONE,
    }),
    [data],
  );

  const submit = useCallback(
    async (values: OrganizationFormValues) => {
      try {
        await updateMyTenant(values).unwrap();
        toast.success('Organization saved.');
        return true;
      } catch (err) {
        toast.error(
          extractApiErrorMessage(err, "Couldn't save organization"),
        );
        return false;
      }
    },
    [updateMyTenant],
  );

  return {
    initialValues,
    submit,
    isLoading,
    isError,
    refetch,
    isSaving: state.isLoading,
    loaded: Boolean(data),
  };
}

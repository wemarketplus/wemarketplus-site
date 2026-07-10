import { useCallback } from 'react';
import { toast } from 'sonner';
import {
  useGetPreferencesQuery,
  useUpdatePreferencesMutation,
} from '../api/notificationsApi';
import type { NotificationPreferenceItem } from '../types/notificationsTypes';

// Orchestrates the notification preference center: loads the per-type in-app
// toggles and persists a single toggle change (optimistic in the API layer,
// with a toast on failure). Keeps NotificationsPreferences presentational.
export function useNotificationPreferences() {
  const { data, isLoading, isError } = useGetPreferencesQuery();
  const [updatePreferences, updateState] = useUpdatePreferencesMutation();

  const toggle = useCallback(
    async (item: NotificationPreferenceItem, nextInApp: boolean) => {
      try {
        await updatePreferences({
          items: [{ type: item.type, inApp: nextInApp }],
        }).unwrap();
      } catch {
        toast.error('Could not update your notification preference.');
      }
    },
    [updatePreferences],
  );

  return {
    items: data?.items ?? [],
    isLoading,
    isError,
    isSaving: updateState.isLoading,
    toggle,
  };
}

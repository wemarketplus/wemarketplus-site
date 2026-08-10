import { useCallback } from 'react';
import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { patchUser } from '@/modules/auth';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useUpdateOwnProfileMutation } from '@/modules/users/api/usersApi';

/**
 * The calendar-colour half of the personal profile page.
 *
 * Separate from useProfileForm even though both PATCH /users/me, because the
 * two behave differently on purpose: the name/email form is a dirty-then-save
 * form, while picking a colour saves on click — a swatch that needed a
 * subsequent "Save" would leave the picker showing a selection the calendar
 * did not have.
 */
export function useCalendarColor() {
  const dispatch = useAppDispatch();
  const current = useAppSelector((s) => s.auth.user?.calendarColor ?? null);
  const [updateOwnProfile, state] = useUpdateOwnProfileMutation();

  const select = useCallback(
    async (calendarColor: string | null) => {
      // Clicking the colour you already have is a no-op, not a wasted round
      // trip that briefly flags the row as saving.
      if (calendarColor === current) return;
      try {
        const saved = await updateOwnProfile({ calendarColor }).unwrap();
        // Updating the cached session user is what makes the change visible
        // everywhere immediately. The Appointments calendar additionally
        // refetches the tenant colour map, which the mutation invalidates.
        dispatch(patchUser({ calendarColor: saved.calendarColor }));
        toast.success(
          calendarColor
            ? 'Calendar colour updated.'
            : 'Back to your automatic colour.',
        );
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't save your colour"));
      }
    },
    [current, dispatch, updateOwnProfile],
  );

  return { current, select, isSaving: state.isLoading };
}

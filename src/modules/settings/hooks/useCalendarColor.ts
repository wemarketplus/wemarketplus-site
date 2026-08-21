import { useCallback } from 'react';
import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { patchUser } from '@/modules/auth';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useUpdateOwnProfileMutation } from '@/modules/users/api/usersApi';

/**
 * ONE toast for this control, reused across every save.
 *
 * Passing a stable id makes Sonner UPDATE the live toast instead of pushing a
 * new one, which is what a save-on-click picker needs: trying four colours in
 * a row otherwise queued four identical "Calendar colour updated." toasts that
 * stacked and overlapped each other (Sonner offsets each new toast ~15px over
 * the last, so the earlier ones were partly hidden behind the newer ones).
 *
 * Replacement is also the honest report. These messages are not four separate
 * facts to read — only the newest one is still true, because each save
 * supersedes the one before it. The success and error toasts deliberately SHARE
 * the id for the same reason: a failure that follows a success must replace it,
 * not sit underneath a stale "updated" the user can still read.
 */
const TOAST_ID = 'calendar-colour';

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
          { id: TOAST_ID },
        );
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't save your colour"), {
          id: TOAST_ID,
        });
      }
    },
    [current, dispatch, updateOwnProfile],
  );

  return { current, select, isSaving: state.isLoading };
}

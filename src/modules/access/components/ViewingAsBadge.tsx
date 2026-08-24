import { useAppSelector } from '@/app/hooks';
import { roleTitle, useRole } from '@/shared/rbac';

/**
 * The "Viewing as" row in the sidebar: WHO YOU ARE SIGNED IN AS, and nothing else.
 *
 * Every end-user guide opens on this control — "Look for the Viewing As dropdown …
 * confirm you're set to <role>" — so it renders for every authenticated user,
 * whatever their role.
 *
 * IT SHOWS ONE ROLE: THE ACTIVE ONE. It does not offer other roles, and there is no
 * way to switch. This replaced a switcher that let a management user preview a
 * lesser persona; offering a list of other people's roles answered a question
 * ("what does a Housekeeper see?") that the control is not for, and made "Viewing
 * as" ambiguous — a reader could not tell whether the row was reporting their role
 * or proposing a change to it. Reporting is the whole job.
 *
 * Not a <button>, not a <select>: nothing happens on interaction, so it must not
 * invite any (same reasoning as the `comingSoon` nav rows). Screen readers get the
 * label and the value as plain text, which is exactly what it is.
 *
 * The label is `roleTitle`, not the raw role: a tenant-defined job title ("Volunteer
 * Coordinator" on a Caregiver base) has to read the same here as in the sidebar
 * footer and the dashboard greeting, or the same person is named two different
 * things on one screen.
 */
export function ViewingAsBadge() {
  const { role } = useRole();
  const customRole = useAppSelector((s) => s.auth.user?.customRole);

  // No session, no role to report.
  if (!role) return null;

  return (
    <div className="mt-2.5">
      <p className="mb-1 text-[9px] font-bold uppercase tracking-label text-muted-soft">
        Viewing as
      </p>
      <span className="inline-block rounded-sm bg-primary/[0.09] px-2 py-1 text-[10px] font-bold uppercase tracking-label text-primary">
        {roleTitle(role, customRole?.name)}
      </span>
    </div>
  );
}

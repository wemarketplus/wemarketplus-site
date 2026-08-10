import { CalendarColorCard } from '../components/CalendarColorCard';
import { ProfileTab } from '../components/ProfileTab';

/**
 * The personal profile page — the ONE settings surface every role can reach.
 *
 * /settings is gated to Admin/Owner (plus Owner/Investor) because it edits the
 * ORGANIZATION: tenant details, integrations, data export. That gate is correct
 * and stays. The consequence, until now, was that a Marketer or Nurse had no
 * settings entry at all and therefore nowhere to change their own name, phone or
 * calendar colour — the account fields that are nobody's business but theirs.
 * This page is that missing surface, at /my-profile, with no role gate.
 *
 * WHY IT LIVES IN THE SETTINGS MODULE rather than a new one: it is assembled
 * entirely from parts settings already owns (ProfileTab, profileSchema,
 * useProfileForm) over an endpoint settings already calls. A separate module
 * would have duplicated the profile form or imported it across a module
 * boundary, and — since it would need its own reducer/api registration — would
 * have added wiring to app/store.ts for no gain. Nothing here is registered
 * anew; only a route and a nav entry are needed.
 *
 * Deliberately NOT tabbed. The admin Settings page uses tabs because it has five
 * unrelated sections; this one has two short cards, and a tab bar over two items
 * is furniture.
 */
export function MyProfilePage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">My profile</h1>
        <p className="text-sm text-muted">
          Your own details and how you appear to the rest of the team.
        </p>
      </div>

      <ProfileTab />
      <CalendarColorCard />
    </div>
  );
}

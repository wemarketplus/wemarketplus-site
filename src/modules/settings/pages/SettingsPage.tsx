import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { ManageCustomRoles } from '@/modules/permissions';
import { ADMIN_ONLY, RoleGate } from '@/shared/rbac';
import { SettingsTabs } from '../components/SettingsTabs';
import { ProfileTab } from '../components/ProfileTab';
import { OrganizationTab } from '../components/OrganizationTab';
import { AccountPlanCard } from '../components/AccountPlanCard';
import { IntegrationsTab } from '../components/IntegrationsTab';
import { SecurityTab } from '../components/SecurityTab';
import { DataExportTab } from '../components/DataExportTab';
import { useSettingsTabs } from '../hooks/useSettingsTabs';

export function SettingsPage() {
  const { activeTab: tab } = useSettingsTabs();

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className={PAGE_TITLE}>Settings</h1>
        <p className="text-sm text-muted">
          Manage your profile, organization, integrations, and security.
        </p>
      </div>

      <SettingsTabs />

      <div className="space-y-6">
        {tab === 'profile' && <ProfileTab />}
        {tab === 'organization' && (
          <>
            <OrganizationTab />
            {/*
              Plan, seats and the invite button sit UNDER the org form because
              the Administrator guide walks all three as one visit: update the
              community's details, check the plan and seat count, invite a team
              member. RoleGate because GET /users/seats is Admin/Owner-only and
              this route also admits CommunityLink's Owner/Investor — the same
              gate UsersPage puts around TeamOverviewStats, for the same reason.
            */}
            <RoleGate allow={ADMIN_ONLY}>
              <AccountPlanCard />
            </RoleGate>
          </>
        )}
        {/*
          The SAME panel the Roles & permissions page renders, not a second copy:
          the CommunityLink guide sends an administrator to Settings for it
          ("In Settings, look for Manage Roles"), while HospiceLink's sends them
          to /permissions. One component, two entry points — see
          modules/permissions/components/ManageCustomRoles.
        */}
        {tab === 'roles' && <ManageCustomRoles />}
        {tab === 'integrations' && <IntegrationsTab />}
        {tab === 'security' && <SecurityTab />}
        {tab === 'data-export' && <DataExportTab />}
      </div>
    </div>
  );
}

import { useAppSelector } from '@/app/hooks';
import { SettingsTabs } from '../components/SettingsTabs';
import { ProfileTab } from '../components/ProfileTab';
import { OrganizationTab } from '../components/OrganizationTab';
import { IntegrationsTab } from '../components/IntegrationsTab';
import { SecurityTab } from '../components/SecurityTab';
import { DataExportTab } from '../components/DataExportTab';

export function SettingsPage() {
  const tab = useAppSelector((s) => s.settings.activeTab);

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Settings</h1>
        <p className="text-sm text-muted">
          Manage your profile, organization, integrations, and security.
        </p>
      </div>

      <SettingsTabs />

      <div>
        {tab === 'profile' && <ProfileTab />}
        {tab === 'organization' && <OrganizationTab />}
        {tab === 'integrations' && <IntegrationsTab />}
        {tab === 'security' && <SecurityTab />}
        {tab === 'data-export' && <DataExportTab />}
      </div>
    </div>
  );
}

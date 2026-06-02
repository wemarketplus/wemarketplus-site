import { AddLeadTab } from '../components/AddLeadTab';
import { AddReferralTab } from '../components/AddReferralTab';
import { AiAssistantTab } from '../components/AiAssistantTab';
import { ClDemoSidebar } from '../components/ClDemoSidebar';
import { ClDemoToast } from '../components/ClDemoToast';
import { ClDemoTopbar } from '../components/ClDemoTopbar';
import { DashboardTab } from '../components/DashboardTab';
import { GpsTab } from '../components/GpsTab';
import { LeadDetailModal } from '../components/LeadDetailModal';
import { LeadPipelineTab } from '../components/LeadPipelineTab';
import { MileageTab } from '../components/MileageTab';
import { NotesTab } from '../components/NotesTab';
import { OutreachTab } from '../components/OutreachTab';
import { ReferralsTab } from '../components/ReferralsTab';
import { ReportsTab } from '../components/ReportsTab';
import { SettingsTab } from '../components/SettingsTab';
import { TasksTab } from '../components/TasksTab';
import { ToursTab } from '../components/ToursTab';
import { useClDemo } from '../hooks/useClDemo';
import type { ComponentType } from 'react';
import type { TabKey } from '../types/clDemoTypes';

// Self-contained CommunityLink Pro CRM demo — a pixel replica of
// communitylinkpro-demo.html. Owns its full-screen shell (sidebar + topbar +
// in-memory tab router) and forces the amber theme via data-product.
const TABS: Record<TabKey, ComponentType> = {
  dashboard: DashboardTab,
  addlead: AddLeadTab,
  leads: LeadPipelineTab,
  refs: ReferralsTab,
  addref: AddReferralTab,
  tours: ToursTab,
  gps: GpsTab,
  mileage: MileageTab,
  outreach: OutreachTab,
  tasks: TasksTab,
  notes: NotesTab,
  ai: AiAssistantTab,
  reports: ReportsTab,
  settings: SettingsTab,
};

export function ClDemoPage() {
  const { activeTab } = useClDemo();
  const ActiveTab = TABS[activeTab];

  return (
    <div data-product="communitylink" className="flex h-screen w-full overflow-hidden bg-[#07111e] text-[#f4f8ff]">
      <ClDemoSidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <ClDemoTopbar />
        <main className="flex-1 overflow-y-auto p-5">
          <ActiveTab />
        </main>
      </div>
      <LeadDetailModal />
      <ClDemoToast />
    </div>
  );
}

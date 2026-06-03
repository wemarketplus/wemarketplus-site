import { DemoToast } from '@/shared/cl-demo';
import { ApartmentsTab } from '../components/ApartmentsTab';
import { DashboardTab } from '../components/DashboardTab';
import { GoldSidebar } from '../components/GoldSidebar';
import { GoldTopbar } from '../components/GoldTopbar';
import { HousekeepingTab } from '../components/HousekeepingTab';
import { LeadsTab } from '../components/LeadsTab';
import { MaintenanceTab } from '../components/MaintenanceTab';
import { MakeReadyTab } from '../components/MakeReadyTab';
import { OccupancyTab } from '../components/OccupancyTab';
import { ReferralsTab } from '../components/ReferralsTab';
import { ReportsTab } from '../components/ReportsTab';
import { SettingsTab } from '../components/SettingsTab';
import { TasksTab } from '../components/TasksTab';
import { ToursTab } from '../components/ToursTab';
import { useGoldDemo } from '../hooks/useGoldDemo';
import type { ComponentType } from 'react';
import type { GoldTabKey } from '../types/goldTypes';

// Self-contained CommunityLink Gold CRM demo — a pixel replica of
// communitylinkgold-demo.html. Owns its full-screen shell (sidebar + topbar +
// in-memory, role-aware tab router) and forces the amber theme via data-product.
const TABS: Record<GoldTabKey, ComponentType> = {
  dashboard: DashboardTab,
  occupancy: OccupancyTab,
  leads: LeadsTab,
  tours: ToursTab,
  refs: ReferralsTab,
  apartments: ApartmentsTab,
  makeready: MakeReadyTab,
  maintenance: MaintenanceTab,
  housekeeping: HousekeepingTab,
  tasks: TasksTab,
  reports: ReportsTab,
  settings: SettingsTab,
};

export function GoldDemoPage() {
  const { activeTab, toast, actions } = useGoldDemo();
  const ActiveTab = TABS[activeTab];

  return (
    <div data-product="communitylink" className="flex h-screen w-full overflow-hidden bg-[#07111e] text-[#f4f8ff]">
      <GoldSidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <GoldTopbar />
        <main className="flex-1 overflow-y-auto p-5">
          <ActiveTab />
        </main>
      </div>
      <DemoToast toast={toast} onHide={actions.hideToast} />
    </div>
  );
}

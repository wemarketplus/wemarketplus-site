import { DemoToast } from '@/shared/cl-demo';
import { AircallTab } from '../components/AircallTab';
import { AlertSettingsTab } from '../components/AlertSettingsTab';
import { ApartmentsTab } from '../components/ApartmentsTab';
import { CompetitorsTab } from '../components/CompetitorsTab';
import { ConcessionsTab } from '../components/ConcessionsTab';
import { DashboardTab } from '../components/DashboardTab';
import { FinSettingsTab } from '../components/FinSettingsTab';
import { GiftTab } from '../components/GiftTab';
import { HousekeepingTab } from '../components/HousekeepingTab';
import { LeadsTab } from '../components/LeadsTab';
import { LedgerTab } from '../components/LedgerTab';
import { LocCalculatorTab } from '../components/LocCalculatorTab';
import { MaintenanceTab } from '../components/MaintenanceTab';
import { MakeReadyTab } from '../components/MakeReadyTab';
import { MaxMobileNav } from '../components/MaxMobileNav';
import { MaxModalHost } from '../components/MaxModalHost';
import { MaxSidebar } from '../components/MaxSidebar';
import { MaxTopbar } from '../components/MaxTopbar';
import { MileageTab } from '../components/MileageTab';
import { NotesTab } from '../components/NotesTab';
import { OccupancyTab } from '../components/OccupancyTab';
import { PaidRefsTab } from '../components/PaidRefsTab';
import { ReferralPipelineTab } from '../components/ReferralPipelineTab';
import { ReferralSourcesTab } from '../components/ReferralSourcesTab';
import { ReportsTab } from '../components/ReportsTab';
import { RevenueLeakageTab } from '../components/RevenueLeakageTab';
import { SettingsTab } from '../components/SettingsTab';
import { TasksTab } from '../components/TasksTab';
import { ToursTab } from '../components/ToursTab';
import { useMaxDemo } from '../hooks/useMaxDemo';
import type { ComponentType } from 'react';
import type { MaxTabKey } from '../types/maxTypes';

// Self-contained CommunityLink Max CRM demo — a pixel replica of
// communitylinkmax-demo.html. Owns its full-screen shell (sidebar + topbar +
// role-aware tab router + mobile nav + modals), forces the amber theme.
const TABS: Record<MaxTabKey, ComponentType> = {
  dashboard: DashboardTab,
  occupancy: OccupancyTab,
  leads: LeadsTab,
  referrals: ReferralPipelineTab,
  paidrefs: PaidRefsTab,
  tours: ToursTab,
  refs: ReferralSourcesTab,
  apartments: ApartmentsTab,
  makeready: MakeReadyTab,
  maintenance: MaintenanceTab,
  housekeeping: HousekeepingTab,
  tasks: TasksTab,
  mileage: MileageTab,
  notes: NotesTab,
  gift: GiftTab,
  alertsettings: AlertSettingsTab,
  finsettings: FinSettingsTab,
  reports: ReportsTab,
  settings: SettingsTab,
  ledger: LedgerTab,
  revenue: RevenueLeakageTab,
  concessions: ConcessionsTab,
  loc: LocCalculatorTab,
  competitors: CompetitorsTab,
  aircall: AircallTab,
};

export function MaxDemoPage() {
  const { activeTab, toast, actions } = useMaxDemo();
  const ActiveTab = TABS[activeTab];

  return (
    <div data-product="communitylink" className="flex h-screen w-full overflow-hidden bg-[#07111e] text-[#f4f8ff]">
      <MaxSidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <MaxTopbar />
        <main className="flex-1 overflow-y-auto p-5 pb-[66px] sm:pb-5">
          <ActiveTab />
        </main>
      </div>
      <DemoToast toast={toast} onHide={actions.hideToast} />
      <MaxModalHost />
      <MaxMobileNav />
    </div>
  );
}

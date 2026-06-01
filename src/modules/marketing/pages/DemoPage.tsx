import { Outlet } from 'react-router-dom';
import { DashboardHeader, Sidebar } from '@/shared/ui/layout';
import { NotificationsDrawer } from '@/modules/notifications';
import { DemoBanner } from '../components/DemoBanner';
import { useDemoParams } from '../hooks/useDemoParams';

// Public-route layout that reuses the authenticated dashboard chrome
// underneath a sticky "demo mode" banner. We inline the same Sidebar +
// DashboardHeader + <Outlet/> shape used by DashboardLayout so React Router's
// nested children resolve correctly.
export function DemoPage() {
  const { product, tier } = useDemoParams();
  return (
    <div className="flex h-screen w-full flex-col bg-bg">
      <DemoBanner product={product} tier={tier} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <div className="flex flex-1 flex-col overflow-hidden">
          <DashboardHeader />
          <main className="flex-1 overflow-y-auto px-6 pb-16 pt-6 sm:px-8">
            <div className="mx-auto max-w-7xl animate-fade-in">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
      <NotificationsDrawer />
    </div>
  );
}

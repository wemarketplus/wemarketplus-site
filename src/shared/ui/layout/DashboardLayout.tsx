import { Outlet } from 'react-router-dom';
import { NotificationsDrawer, useNotificationsStream } from '@/modules/notifications';
import { ImpersonationBanner } from '@/modules/owner-portal';
import { Sidebar } from './Sidebar';
import { DashboardHeader } from './DashboardHeader';

// Mirrors wemarketplus-site `.layout` / `.main`: flex shell, 100vh, the main
// column scrolls on #081426 with `.main-inner` padding (18px 22px 60px).
// The CRM content is full-width (no max-width clamp) — matching the source.
export function DashboardLayout() {
  // Single realtime subscription for the authenticated shell: pushes new
  // notifications into the drawer/page/bell as they arrive.
  useNotificationsStream();
  return (
    <div className="flex h-screen w-full overflow-hidden bg-bg">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Persistent banner while a SuperAdmin impersonates a tenant. Renders
            nothing when not impersonating. */}
        <ImpersonationBanner />
        <DashboardHeader />
        <main className="flex-1 overflow-y-auto bg-bg px-[22px] pb-[60px] pt-[18px]">
          <div className="animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>
      {/* Drawer lives at the layout level so any page can open it via dispatch
          without each page needing to mount its own portal. */}
      <NotificationsDrawer />
    </div>
  );
}

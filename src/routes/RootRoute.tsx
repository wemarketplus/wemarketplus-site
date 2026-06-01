import { useAppSelector } from '@/app/hooks';
import { LandingPage } from '@/modules/marketing';
import { DashboardPage } from '@/modules/dashboard';
import { Sidebar, DashboardHeader } from '@/shared/ui/layout';
import { NotificationsDrawer } from '@/modules/notifications';

// Picks the right "/" experience based on auth state. Mirrors the live site,
// where wemarketplus.com is a marketing page for visitors and the CRM home
// for authenticated users.
//
// Inlines the dashboard chrome instead of using <DashboardLayout> so the
// authenticated branch renders DashboardPage as a direct child (DashboardLayout
// uses <Outlet/> which won't resolve at a top-level route).
export function RootRoute() {
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);

  if (!isAuthenticated) {
    return <LandingPage />;
  }

  return (
    <div className="flex h-screen w-full bg-bg">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <DashboardHeader />
        <main className="flex-1 overflow-y-auto px-6 pb-16 pt-6 sm:px-8">
          <div className="mx-auto max-w-7xl animate-fade-in">
            <DashboardPage />
          </div>
        </main>
      </div>
      <NotificationsDrawer />
    </div>
  );
}

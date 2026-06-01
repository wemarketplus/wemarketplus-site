import { Outlet } from 'react-router-dom';
import { OwnerSidebar } from './OwnerSidebar';
import { DashboardHeader } from '@/shared/ui/layout/DashboardHeader';

// Owner portal reuses the main DashboardHeader (signed-in user identity +
// notifications + sign-out) so global state stays consistent. The sidebar is
// owner-specific.
export function OwnerLayout() {
  return (
    <div className="flex h-screen w-full bg-bg">
      <OwnerSidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <DashboardHeader />
        <main className="flex-1 overflow-y-auto px-6 pb-16 pt-6 sm:px-8">
          <div className="mx-auto max-w-7xl animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

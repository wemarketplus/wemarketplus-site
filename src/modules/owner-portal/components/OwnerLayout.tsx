import { Outlet } from 'react-router-dom';
import { OwnerSidebar } from './OwnerSidebar';
import { DashboardHeader } from '@/shared/ui/layout/DashboardHeader';
import {
  SHELL_CONTENT_PADDING,
  SHELL_MAIN_SCROLL,
} from '@/shared/ui/layout/shellStyles';

// Owner portal reuses the main DashboardHeader (signed-in user identity +
// notifications + sign-out) so global state stays consistent. The sidebar is
// owner-specific.
export function OwnerLayout() {
  return (
    <div className="flex h-screen w-full bg-bg">
      <OwnerSidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Same arrangement as DashboardLayout — topbar sticky INSIDE the
            scroll container, gutter on the content wrapper, no `max-w-7xl`
            clamp. This shell wears the SAME DashboardHeader, so padding the
            page differently from the topbar is what left "Sign out" overhanging
            the content edge here. See shellStyles.ts. */}
        <main className={`flex-1 overflow-y-auto ${SHELL_MAIN_SCROLL}`}>
          <DashboardHeader />
          <div className={`animate-fade-in ${SHELL_CONTENT_PADDING}`}>
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

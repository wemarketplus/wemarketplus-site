import type { ReactNode } from 'react';
import { Outlet } from 'react-router-dom';
import { CopilotLauncher } from '@/modules/ai-assistant';
import { NotificationsDrawer, useNotificationsStream } from '@/modules/notifications';
import { ImpersonationBanner } from '@/modules/owner-portal';
import { Sidebar } from './Sidebar';
import { DashboardHeader } from './DashboardHeader';
import {
  SHELL_CONTENT_PADDING,
  SHELL_MAIN_SCROLL,
} from './shellStyles';

interface DashboardLayoutProps {
  /**
   * The page, for the ONE route that cannot use `<Outlet/>`.
   *
   * `/` picks between the marketing landing page and the CRM home at render
   * time (see routes/RootRoute), so its page component is a direct child rather
   * than a nested route — and `<Outlet/>` does not resolve at a top-level route.
   * RootRoute therefore used to inline its own copy of this whole shell, which
   * drifted: it padded `<main>` `px-6 sm:px-8` against this file's `px-[22px]`,
   * clamped the page to `max-w-7xl` where no other screen does, dropped
   * `overflow-hidden` from the flex root, and never mounted CopilotLauncher or
   * ImpersonationBanner. So the home dashboard was a visibly different shell
   * from every other page, under a topbar that matched neither.
   *
   * Taking children instead means there is one shell, not two that have to be
   * kept in step by hand.
   */
  children?: ReactNode;
}

// Mirrors wemarketplus-site `.layout` / `.main`: flex shell, 100vh, the main
// column scrolls with `.main-inner` padding. The CRM content is full-width (no
// max-width clamp) — matching the source.
//
// ONE scroll container. `<main>` is the only thing that scrolls, and the topbar
// is a STICKY ROW INSIDE it rather than a sibling above it — that is what makes
// the topbar and the page share a content box, and therefore both edges. The
// horizontal gutter lives on the content wrapper and on the topbar (both
// SHELL_GUTTER_X), never on `<main>`, so the topbar can sit flush against the
// top of the scroll box. See shellStyles.ts.
export function DashboardLayout({ children }: DashboardLayoutProps) {
  // Single realtime subscription for the authenticated shell: pushes new
  // notifications into the drawer/page/bell as they arrive.
  useNotificationsStream();
  return (
    <div className="flex h-screen w-full overflow-hidden bg-bg">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Persistent banner while a SuperAdmin impersonates a tenant. Renders
            nothing when not impersonating. */}
        {/* Stays OUTSIDE the scroll container: an impersonation warning must
            not scroll away. The topbar then sticks to the top of the scroll box
            directly beneath it. */}
        <ImpersonationBanner />
        <main className={`flex-1 overflow-y-auto bg-bg ${SHELL_MAIN_SCROLL}`}>
          <DashboardHeader />
          <div className={`animate-fade-in ${SHELL_CONTENT_PADDING}`}>
            {children ?? <Outlet />}
          </div>
        </main>
      </div>
      {/* Drawer lives at the layout level so any page can open it via dispatch
          without each page needing to mount its own portal. */}
      <NotificationsDrawer />
      {/* Floating Copilot — same reasoning as the drawer: one mount for the whole
          authenticated shell, so it follows a field technician from their queue onto
          a ticket instead of appearing and vanishing per page. Renders null for
          every role that has the AI assistant in its nav. */}
      <CopilotLauncher />
    </div>
  );
}

import { useAppSelector } from '@/app/hooks';
import { LandingPage } from '@/modules/marketing';
import { DashboardPage } from '@/modules/dashboard';
import { DashboardLayout } from '@/shared/ui/layout';

// Picks the right "/" experience based on auth state. Mirrors the live site,
// where wemarketplus.com is a marketing page for visitors and the CRM home
// for authenticated users.
//
// The authenticated branch renders the REAL <DashboardLayout>, passing the page
// as children because `<Outlet/>` does not resolve at a top-level route. It used
// to inline its own copy of the shell instead, which had quietly diverged from
// the one every other screen uses — different `<main>` gutter (32px against
// 22px), a `max-w-7xl` clamp no other page has, and no CopilotLauncher or
// ImpersonationBanner. The visible symptom was the topbar: with the page inset
// 32px and clamped, "Sign out" overhung the content beneath it by ~25px on this
// screen and by nothing on the others, and moving from `/` to any list page slid
// the whole page sideways under a topbar that stayed put.
export function RootRoute() {
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);

  if (!isAuthenticated) {
    return <LandingPage />;
  }

  return (
    <DashboardLayout>
      <DashboardPage />
    </DashboardLayout>
  );
}

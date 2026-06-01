import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { DashboardLayout } from '@/shared/ui/layout';
import { PublicRoute } from '@/routes/PublicRoute';
import { RootRoute } from '@/routes/RootRoute';
// NOTE: auth gates are intentionally commented out below so dev can browse
// every screen without logging in. When ready, re-import ProtectedRoute and
// the role groups from @/routes/ProtectedRoute and @/shared/rbac.

// --- Public auth funnel ---------------------------------------------------

const AuthPage = lazy(() =>
  import('@/modules/auth').then((m) => ({ default: m.AuthPage })),
);
const ForgotPasswordPage = lazy(() =>
  import('@/modules/auth').then((m) => ({ default: m.ForgotPasswordPage })),
);
const ResetPasswordPage = lazy(() =>
  import('@/modules/auth').then((m) => ({ default: m.ResetPasswordPage })),
);
const AcceptInvitePage = lazy(() =>
  import('@/modules/auth').then((m) => ({ default: m.AcceptInvitePage })),
);
const OnboardingPage = lazy(() =>
  import('@/modules/onboarding').then((m) => ({ default: m.OnboardingPage })),
);
const ChangePasswordPage = lazy(() =>
  import('@/modules/auth').then((m) => ({ default: m.ChangePasswordPage })),
);

// --- Marketing (public) ---------------------------------------------------

const PricingPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({ default: m.PricingPage })),
);
const CommunityLinkLandingPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({
    default: m.CommunityLinkLandingPage,
  })),
);
const CommunityLinkPricingPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({
    default: m.CommunityLinkPricingPage,
  })),
);
const PrivacyPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({ default: m.PrivacyPage })),
);
const TermsPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({ default: m.TermsPage })),
);
const CompliancePublicPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({
    default: m.CompliancePublicPage,
  })),
);
const SignBaaPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({ default: m.SignBaaPage })),
);
const ThankYouPage = lazy(() =>
  import('@/modules/marketing').then((m) => ({ default: m.ThankYouPage })),
);
const DemoPage = lazy(() =>
  import('@/modules/marketing/pages/DemoPage').then((m) => ({
    default: m.DemoPage,
  })),
);

// --- Dashboard children (cross-product) -----------------------------------

const DashboardPage = lazy(() =>
  import('@/modules/dashboard').then((m) => ({ default: m.DashboardPage })),
);
const UsersPage = lazy(() =>
  import('@/modules/users').then((m) => ({ default: m.UsersPage })),
);
const PermissionsPage = lazy(() =>
  import('@/modules/permissions').then((m) => ({ default: m.PermissionsPage })),
);
const NotificationsPage = lazy(() =>
  import('@/modules/notifications').then((m) => ({ default: m.NotificationsPage })),
);
const SubscriptionStatusPage = lazy(() =>
  import('@/modules/billing').then((m) => ({ default: m.SubscriptionStatusPage })),
);
const SettingsPage = lazy(() =>
  import('@/modules/settings').then((m) => ({ default: m.SettingsPage })),
);

// --- HospiceLink screens --------------------------------------------------

const ProspectsPage = lazy(() =>
  import('@/modules/prospects').then((m) => ({ default: m.ProspectsPage })),
);
const ReferralsPage = lazy(() =>
  import('@/modules/referrals').then((m) => ({ default: m.ReferralsPage })),
);
const PipelinePage = lazy(() =>
  import('@/modules/pipeline').then((m) => ({ default: m.PipelinePage })),
);
const SchedulingPage = lazy(() =>
  import('@/modules/scheduling').then((m) => ({ default: m.SchedulingPage })),
);
const ActivityPage = lazy(() =>
  import('@/modules/activity').then((m) => ({ default: m.ActivityPage })),
);
const AiAssistantPage = lazy(() =>
  import('@/modules/ai-assistant').then((m) => ({ default: m.AiAssistantPage })),
);
const ClinicalPage = lazy(() =>
  import('@/modules/clinical').then((m) => ({ default: m.ClinicalPage })),
);
const IntelligencePage = lazy(() =>
  import('@/modules/intelligence').then((m) => ({ default: m.IntelligencePage })),
);
const IntegrationsPage = lazy(() =>
  import('@/modules/integrations').then((m) => ({ default: m.IntegrationsPage })),
);
const CompliancePage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.CompliancePage })),
);
const ReadinessPage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.ReadinessPage })),
);
const AccessReviewPage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.AccessReviewPage })),
);
const DrTestPage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.DrTestPage })),
);
const BreachWorkflowPage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.BreachWorkflowPage })),
);
const EvidenceExportPage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.EvidenceExportPage })),
);
const BaaRecordsPage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.BaaRecordsPage })),
);
const ThreatMonitorPage = lazy(() =>
  import('@/modules/compliance').then((m) => ({ default: m.ThreatMonitorPage })),
);

// --- CommunityLink screens ------------------------------------------------

const LeadsPage = lazy(() =>
  import('@/modules/cl-leads').then((m) => ({ default: m.LeadsPage })),
);
const ClReferralsPage = lazy(() =>
  import('@/modules/cl-referrals').then((m) => ({ default: m.ClReferralsPage })),
);
const ClToursPage = lazy(() =>
  import('@/modules/cl-tours').then((m) => ({ default: m.ClToursPage })),
);
const ClOutreachPage = lazy(() =>
  import('@/modules/cl-outreach').then((m) => ({ default: m.ClOutreachPage })),
);
const ClOperationsPage = lazy(() =>
  import('@/modules/cl-operations').then((m) => ({ default: m.ClOperationsPage })),
);
const ClFinancialPage = lazy(() =>
  import('@/modules/cl-financial').then((m) => ({ default: m.ClFinancialPage })),
);
const ClReportsPage = lazy(() =>
  import('@/modules/cl-reports').then((m) => ({ default: m.ClReportsPage })),
);

// --- Owner portal ---------------------------------------------------------

const OwnerLayout = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerLayout })),
);
const OwnerDashboardPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerDashboardPage })),
);
const OwnerRevenuePage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerRevenuePage })),
);
const OwnerCustomersPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerCustomersPage })),
);
const OwnerPipelinePage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerPipelinePage })),
);
const OwnerVisitorsPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerVisitorsPage })),
);
const OwnerMarketingPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerMarketingPage })),
);
const OwnerChurnPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerChurnPage })),
);
const OwnerUsagePage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerUsagePage })),
);
const OwnerInsightsPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerInsightsPage })),
);
const OwnerCommunicationPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerCommunicationPage })),
);
const OwnerSecurityPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerSecurityPage })),
);
const OwnerAdminControlsPage = lazy(() =>
  import('@/modules/owner-portal').then((m) => ({ default: m.OwnerAdminControlsPage })),
);

const RouteFallback = () => (
  <div className="flex h-full w-full items-center justify-center text-sm text-muted">
    Loading…
  </div>
);

export function AppRouter() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        {/* "/" — marketing for visitors, dashboard for authenticated users */}
        <Route path="/" element={<RootRoute />} />

        {/* Public marketing — direct URL matches to wemarketplus-site files */}
        <Route path="/pricing" element={<PricingPage />} />
        <Route path="/communitylink" element={<CommunityLinkLandingPage />} />
        <Route path="/communitylink/pricing" element={<CommunityLinkPricingPage />} />
        <Route path="/privacy" element={<PrivacyPage />} />
        <Route path="/terms" element={<TermsPage />} />
        <Route path="/compliance" element={<CompliancePublicPage />} />
        <Route path="/sign-baa" element={<SignBaaPage />} />
        <Route path="/thank-you" element={<ThankYouPage />} />

        {/* Demo — public route reusing dashboard chrome under a banner */}
        <Route path="/demo/:product/:tier" element={<DemoPage />}>
          <Route index element={<DashboardPage />} />
          <Route path="prospects" element={<ProspectsPage />} />
          <Route path="pipeline" element={<PipelinePage />} />
          <Route path="referrals" element={<ReferralsPage />} />
          <Route path="leads" element={<LeadsPage />} />
          <Route path="operations" element={<ClOperationsPage />} />
        </Route>

        {/* Public auth funnel */}
        <Route
          path="/login"
          element={
            <PublicRoute>
              <AuthPage />
            </PublicRoute>
          }
        />
        {/* CommunityLink-branded login — alias for /login today, same form */}
        <Route
          path="/cl-login"
          element={
            <PublicRoute>
              <AuthPage />
            </PublicRoute>
          }
        />
        <Route
          path="/forgot-password"
          element={
            <PublicRoute>
              <ForgotPasswordPage />
            </PublicRoute>
          }
        />
        <Route
          path="/reset-password"
          element={
            <PublicRoute>
              <ResetPasswordPage />
            </PublicRoute>
          }
        />
        <Route
          path="/accept-invite"
          element={
            <PublicRoute>
              <AcceptInvitePage />
            </PublicRoute>
          }
        />
        <Route
          path="/onboarding"
          element={
            <PublicRoute>
              <OnboardingPage />
            </PublicRoute>
          }
        />

        {/* Protected app — dashboard shell. The shell renders dashboard
            children inside <DashboardLayout>'s <Outlet/>. The index ("/")
            is handled by RootRoute above, so this block has no index. */}
        <Route
          element={
            // <ProtectedRoute>
              <DashboardLayout />
            // </ProtectedRoute>
          }
        >
          {/* HospiceLink */}
          <Route path="prospects" element={<ProspectsPage />} />
          <Route path="referrals" element={<ReferralsPage />} />
          <Route path="pipeline" element={<PipelinePage />} />
          <Route path="territories" element={<SchedulingPage />} />
          <Route path="scheduling" element={<SchedulingPage />} />
          <Route path="activity/calendar" element={<ActivityPage />} />
          <Route path="activity/notes" element={<ActivityPage />} />
          <Route path="activity/reminders" element={<ActivityPage />} />
          <Route path="activity/goals" element={<ActivityPage />} />
          <Route path="activity/ai" element={<AiAssistantPage />} />
          <Route path="clinical/family" element={<ClinicalPage />} />
          <Route path="clinical/messaging" element={<ClinicalPage />} />
          <Route path="clinical/admissions" element={<ClinicalPage />} />
          <Route path="intelligence/revenue" element={<IntelligencePage />} />
          <Route path="intelligence/marketing-roi" element={<IntelligencePage />} />
          <Route path="intelligence/leaderboard" element={<IntelligencePage />} />
          <Route path="integrations/import" element={<IntegrationsPage />} />
          <Route path="integrations/aircall" element={<IntegrationsPage />} />
          <Route path="integrations/playbooks" element={<IntegrationsPage />} />
          <Route path="compliance" element={<ReadinessPage />} />
          <Route path="compliance/readiness" element={<ReadinessPage />} />
          <Route path="compliance/audit" element={<CompliancePage />} />
          <Route path="compliance/access-review" element={<AccessReviewPage />} />
          <Route path="compliance/dr-test" element={<DrTestPage />} />
          <Route path="compliance/breach" element={<BreachWorkflowPage />} />
          <Route path="compliance/evidence" element={<EvidenceExportPage />} />
          <Route path="compliance/baa-records" element={<BaaRecordsPage />} />
          <Route path="compliance/threat-monitor" element={<ThreatMonitorPage />} />

          {/* CommunityLink */}
          <Route path="leads" element={<LeadsPage />} />
          <Route path="cl-referrals" element={<ClReferralsPage />} />
          <Route path="tours" element={<ClToursPage />} />
          <Route path="outreach/checkin" element={<ClOutreachPage />} />
          <Route path="outreach/mileage" element={<ClOutreachPage />} />
          <Route path="outreach/log" element={<ClOutreachPage />} />
          <Route path="operations/inventory" element={<ClOperationsPage />} />
          <Route path="operations/make-ready" element={<ClOperationsPage />} />
          <Route path="operations/maintenance" element={<ClOperationsPage />} />
          <Route path="operations/housekeeping" element={<ClOperationsPage />} />
          <Route path="financial/ledger" element={<ClFinancialPage />} />
          <Route path="financial/leakage" element={<ClFinancialPage />} />
          <Route path="reports" element={<ClReportsPage />} />

          {/* Cross-product admin */}
          <Route path="users" element={<UsersPage />} />
          <Route path="permissions" element={<PermissionsPage />} />
          <Route path="notifications" element={<NotificationsPage />} />
          {/* Billing has two URL spellings — the site uses /subscription-status,
              the new app's chrome links to /billing. Both resolve. */}
          <Route path="billing" element={<SubscriptionStatusPage />} />
          <Route path="subscription-status" element={<SubscriptionStatusPage />} />
          <Route path="settings" element={<SettingsPage />} />
          {/* Change-password is available both as the legacy site URL and the
              nested /account/password we already linked from settings. */}
          <Route path="change-password" element={<ChangePasswordPage />} />
          <Route path="account/password" element={<ChangePasswordPage />} />
        </Route>

        {/* Owner portal — its own chrome */}
        <Route path="/owner" element={<OwnerLayout />}>
          <Route index element={<OwnerDashboardPage />} />
          <Route path="revenue" element={<OwnerRevenuePage />} />
          <Route path="customers" element={<OwnerCustomersPage />} />
          <Route path="pipeline" element={<OwnerPipelinePage />} />
          <Route path="visitors" element={<OwnerVisitorsPage />} />
          <Route path="marketing" element={<OwnerMarketingPage />} />
          <Route path="churn" element={<OwnerChurnPage />} />
          <Route path="usage" element={<OwnerUsagePage />} />
          <Route path="insights" element={<OwnerInsightsPage />} />
          <Route path="communication" element={<OwnerCommunicationPage />} />
          <Route path="security" element={<OwnerSecurityPage />} />
          <Route path="admin-controls" element={<OwnerAdminControlsPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}

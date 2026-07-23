import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { DashboardLayout } from '@/shared/ui/layout';
import { ProtectedRoute } from '@/routes/ProtectedRoute';
import { PublicRoute } from '@/routes/PublicRoute';
import { RequireEntitlement } from '@/routes/RequireEntitlement';
import { RequireRoleAtTier } from '@/routes/RequireRoleAtTier';
import { Tier } from '@/shared/types';
import { RootRoute } from '@/routes/RootRoute';
import { LEGACY_DEMO_REDIRECTS } from '@/shared/config/demoUrls';
import {
  Role,
  SUPER_ADMIN_ONLY,
  ADMIN_ONLY,
  STAFF_ROLES,
  CL_MANAGEMENT_ROLES,
  CL_SALES_ROLES,
  CL_ALL_ROLES,
  CL_INVENTORY_ROLES,
  CL_MAKE_READY_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_HOUSEKEEPING_ROLES,
  CL_FINANCIAL_ROLES,
  CL_UNIT_STATUS_ROLES,
  CL_MAINTENANCE_VIEW_ROLES,
  CL_COMPETITOR_INTEL_ROLES,
  CL_FIELD_ACTIVITY_ROLES,
} from '@/shared/rbac';

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
const VerifyEmailPage = lazy(() =>
  import('@/modules/auth').then((m) => ({ default: m.VerifyEmailPage })),
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
  import('@/modules/marketing').then((m) => ({
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
const ContactsPage = lazy(() =>
  import('@/modules/contacts').then((m) => ({ default: m.ContactsPage })),
);
const CompaniesPage = lazy(() =>
  import('@/modules/companies').then((m) => ({ default: m.CompaniesPage })),
);
// Phase 4 domain modules (backend-only until now) — entity-kit CRUD pages.
const InvoicesPage = lazy(() =>
  import('@/modules/invoices').then((m) => ({ default: m.InvoicesPage })),
);
const ContractsPage = lazy(() =>
  import('@/modules/contracts').then((m) => ({ default: m.ContractsPage })),
);
const FinanceOverviewPage = lazy(() =>
  import('@/modules/finance').then((m) => ({ default: m.FinanceOverviewPage })),
);
const FundingPage = lazy(() =>
  import('@/modules/funding').then((m) => ({ default: m.FundingPage })),
);
const ApplicationsPage = lazy(() =>
  import('@/modules/applications').then((m) => ({ default: m.ApplicationsPage })),
);
const AgreementsPage = lazy(() =>
  import('@/modules/agreements').then((m) => ({ default: m.AgreementsPage })),
);
const WibsPage = lazy(() =>
  import('@/modules/wibs').then((m) => ({ default: m.WibsPage })),
);
const LocationsPage = lazy(() =>
  import('@/modules/locations').then((m) => ({ default: m.LocationsPage })),
);
const TerritoriesEntityPage = lazy(() =>
  import('@/modules/territories').then((m) => ({ default: m.TerritoriesPage })),
);
const TrainingProvidersPage = lazy(() =>
  import('@/modules/training-providers').then((m) => ({
    default: m.TrainingProvidersPage,
  })),
);
const DocumentsPage = lazy(() =>
  import('@/modules/documents').then((m) => ({ default: m.DocumentsPage })),
);
const DataImportExportPage = lazy(() =>
  import('@/modules/admin').then((m) => ({ default: m.DataImportExportPage })),
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
const PaidReferralsPage = lazy(() =>
  import('@/modules/cl-referrals').then((m) => ({ default: m.PaidReferralsPage })),
);
const ClToursPage = lazy(() =>
  import('@/modules/cl-tours').then((m) => ({ default: m.ClToursPage })),
);
const TasksPage = lazy(() =>
  import('@/modules/cl-tasks').then((m) => ({ default: m.TasksPage })),
);
const ClOutreachPage = lazy(() =>
  import('@/modules/cl-outreach').then((m) => ({ default: m.ClOutreachPage })),
);
const ClOperationsPage = lazy(() =>
  import('@/modules/cl-operations').then((m) => ({ default: m.ClOperationsPage })),
);
const OccupancyOverviewPage = lazy(() =>
  import('@/modules/cl-operations').then((m) => ({ default: m.OccupancyOverviewPage })),
);
const ClFinancialPage = lazy(() =>
  import('@/modules/cl-financial').then((m) => ({ default: m.ClFinancialPage })),
);
const ReferralPipelinePage = lazy(() =>
  import('@/modules/cl-referrals').then((m) => ({ default: m.ReferralPipelinePage })),
);
const ActivityNotesPage = lazy(() =>
  import('@/modules/cl-leads').then((m) => ({ default: m.ActivityNotesPage })),
);
const GiftGratuityPage = lazy(() =>
  import('@/modules/cl-gift-gratuity').then((m) => ({ default: m.GiftGratuityPage })),
);
const AircallPage = lazy(() =>
  import('@/modules/cl-aircall').then((m) => ({ default: m.AircallPage })),
);
const AlertSettingsPage = lazy(() =>
  import('@/modules/cl-admin-settings').then((m) => ({ default: m.AlertSettingsPage })),
);
const FinancialSettingsPage = lazy(() =>
  import('@/modules/cl-admin-settings').then((m) => ({ default: m.FinancialSettingsPage })),
);
const ClReportsPage = lazy(() =>
  import('@/modules/cl-reports').then((m) => ({ default: m.ClReportsPage })),
);
// Self-contained CommunityLink Pro CRM demo (pixel replica of
// communitylinkpro-demo.html — own sidebar/topbar/tabs, forced amber theme).
const ClDemoPage = lazy(() =>
  import('@/modules/cl-demo').then((m) => ({ default: m.ClDemoPage })),
);
// Self-contained CommunityLink Gold CRM demo (pixel replica of
// communitylinkgold-demo.html — own sidebar/topbar/role-aware tabs, amber theme).
const GoldDemoPage = lazy(() =>
  import('@/modules/cl-demo-gold').then((m) => ({ default: m.GoldDemoPage })),
);
// Self-contained CommunityLink Max CRM demo (pixel replica of
// communitylinkmax-demo.html — 7 roles, premium financial/activity modules,
// modals, mobile nav).
const MaxDemoPage = lazy(() =>
  import('@/modules/cl-demo-max').then((m) => ({ default: m.MaxDemoPage })),
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
const FeatureFlagsPage = lazy(() =>
  import('@/modules/feature-flags').then((m) => ({ default: m.FeatureFlagsPage })),
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

        {/* CommunityLink Pro CRM demo — self-contained replica of
            communitylinkpro-demo.html. Static path outranks the generic
            /demo/:product/:tier below, so only this exact URL gets the replica. */}
        <Route path="/demo/communitylink/pro" element={<ClDemoPage />} />
        <Route path="/demo/communitylink/gold" element={<GoldDemoPage />} />
        <Route path="/demo/communitylink/max" element={<MaxDemoPage />} />

        {/* Retired HospiceLink demos — redirect to the matching CommunityLink
            demo route. Fully static paths, so they outrank /demo/:product/:tier. */}
        {LEGACY_DEMO_REDIRECTS.map(({ from, to }) => (
          <Route key={from} path={from} element={<Navigate to={to} replace />} />
        ))}

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
            <PublicRoute allowAuthenticated>
              <AcceptInvitePage />
            </PublicRoute>
          }
        />
        {/* Deliberately NOT wrapped in <PublicRoute> — verifying logs the
            user in mid-render, and PublicRoute would bounce them to "/"
            before the page can forward them to /billing. */}
        <Route path="/verify-email" element={<VerifyEmailPage />} />
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
            <ProtectedRoute>
              <DashboardLayout />
            </ProtectedRoute>
          }
        >
          {/* HospiceLink */}
          <Route path="prospects" element={<ProspectsPage />} />
          <Route path="referrals" element={<ReferralsPage />} />
          <Route path="pipeline" element={<PipelinePage />} />
          <Route path="territories" element={<TerritoriesEntityPage />} />
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
          <Route path="integrations/import" element={<DataImportExportPage />} />
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
          <Route
            path="occupancy-overview"
            element={
              <RequireRoleAtTier
                windows={[
                  { minTier: Tier.Gold, maxTier: Tier.Gold, allow: [Role.SuperAdmin, Role.Director] },
                  { minTier: Tier.Max, allow: CL_FINANCIAL_ROLES },
                ]}
              >
                <OccupancyOverviewPage />
              </RequireRoleAtTier>
            }
          />
          <Route path="leads" element={<ProtectedRoute allow={CL_SALES_ROLES}><LeadsPage /></ProtectedRoute>} />
          <Route path="referral-pipeline" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_SALES_ROLES}><ReferralPipelinePage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="cl-referrals" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClReferralsPage /></ProtectedRoute>} />
          <Route path="paid-referrals" element={<ProtectedRoute allow={CL_SALES_ROLES}><PaidReferralsPage /></ProtectedRoute>} />
          <Route path="tours" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClToursPage /></ProtectedRoute>} />
          <Route path="ai-assistant" element={<ProtectedRoute allow={CL_SALES_ROLES}><AiAssistantPage /></ProtectedRoute>} />
          <Route path="activity-notes" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_SALES_ROLES}><ActivityNotesPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="gift-gratuity" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_FIELD_ACTIVITY_ROLES}><GiftGratuityPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="aircall" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_SALES_ROLES}><AircallPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="alert-settings" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={ADMIN_ONLY}><AlertSettingsPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="financial-settings" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={ADMIN_ONLY}><FinancialSettingsPage /></ProtectedRoute></RequireEntitlement>} />
          {/* Tasks is visible/usable by every CommunityLink role, including
              the field roles — matches every role's sidebar in the demo. */}
          <Route path="tasks" element={<ProtectedRoute allow={CL_ALL_ROLES}><TasksPage /></ProtectedRoute>} />
          <Route path="outreach/checkin" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClOutreachPage /></ProtectedRoute>} />
          <Route path="outreach/mileage" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClOutreachPage /></ProtectedRoute>} />
          <Route path="outreach/log" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClOutreachPage /></ProtectedRoute>} />
          {/* CommunityLink Operations — Gold tier and up (product-aware). */}
          <Route path="operations/communities" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={CL_INVENTORY_ROLES}><ClOperationsPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="operations/inventory" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={CL_INVENTORY_ROLES}><ClOperationsPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="operations/make-ready" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={CL_MAKE_READY_ROLES}><ClOperationsPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="operations/maintenance" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={CL_MAINTENANCE_ROLES}><ClOperationsPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="operations/housekeeping" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={CL_HOUSEKEEPING_ROLES}><ClOperationsPage /></ProtectedRoute></RequireEntitlement>} />
          {/* Max-tier-only read-only surfaces for the field roles. */}
          <Route path="operations/unit-status" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_UNIT_STATUS_ROLES}><ClOperationsPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="operations/maintenance-view" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_MAINTENANCE_VIEW_ROLES}><ClOperationsPage /></ProtectedRoute></RequireEntitlement>} />
          {/* CommunityLink Financial — Max tier only (top tier). */}
          <Route path="financial/ledger" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_FINANCIAL_ROLES}><ClFinancialPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="financial/leakage" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_FINANCIAL_ROLES}><ClFinancialPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="financial/concessions" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_FINANCIAL_ROLES}><ClFinancialPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="financial/competitors" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_COMPETITOR_INTEL_ROLES}><ClFinancialPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="financial/loc" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_FINANCIAL_ROLES}><ClFinancialPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="reports" element={<ProtectedRoute allow={CL_MANAGEMENT_ROLES}><ClReportsPage /></ProtectedRoute>} />

          {/* Grant CRM — contacts & employer companies */}
          <Route path="contacts" element={<ContactsPage />} />
          <Route path="companies" element={<CompaniesPage />} />

          {/* Phase 4 domain modules */}
          <Route path="invoices" element={<InvoicesPage />} />
          <Route path="contracts" element={<ContractsPage />} />
          <Route path="finance" element={<FinanceOverviewPage />} />
          <Route path="funding" element={<FundingPage />} />
          <Route path="applications" element={<ApplicationsPage />} />
          <Route path="agreements" element={<AgreementsPage />} />
          <Route path="wibs" element={<WibsPage />} />
          <Route path="locations" element={<LocationsPage />} />
          <Route path="territories-list" element={<TerritoriesEntityPage />} />
          /<Route path="training-providers" element={<TrainingProvidersPage />} />
          <Route path="documents" element={<DocumentsPage />} />

          {/* Cross-product admin. Role-guarded at the route level (not just
              nav-hidden) so a lower role that types the URL is turned away to
              "/" — which always renders the Dashboard, so there is no loop. */}
          <Route path="users" element={<ProtectedRoute allow={STAFF_ROLES}><UsersPage /></ProtectedRoute>} />
          <Route path="permissions" element={<ProtectedRoute allow={ADMIN_ONLY}><PermissionsPage /></ProtectedRoute>} />
          <Route path="notifications" element={<NotificationsPage />} />
          {/* Billing has two URL spellings — the site uses /subscription-status,
              the new app's chrome links to /billing. Both resolve. */}
          <Route path="billing" element={<SubscriptionStatusPage />} />
          <Route path="subscription-status" element={<SubscriptionStatusPage />} />
          <Route path="settings" element={<ProtectedRoute allow={ADMIN_ONLY}><SettingsPage /></ProtectedRoute>} />
          {/* Change-password is available both as the legacy site URL and the
              nested /account/password we already linked from settings. */}
          <Route path="change-password" element={<ChangePasswordPage />} />
          <Route path="account/password" element={<ChangePasswordPage />} />
        </Route>

        {/* Owner portal — its own chrome. Platform-level: the backend now
            requires SuperAdmin on /owner/* (tenant Admin/Owner get 403), so
            mirror that gate here. */}
        <Route
          path="/owner"
          element={
            <ProtectedRoute allow={SUPER_ADMIN_ONLY}>
              <OwnerLayout />
            </ProtectedRoute>
          }
        >
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
          {/* Runtime feature flags — SuperAdmin management surface, gated by the
              same SUPER_ADMIN_ONLY chrome as the rest of /owner/*. */}
          <Route path="feature-flags" element={<FeatureFlagsPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}

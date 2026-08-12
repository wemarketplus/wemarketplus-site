import { lazy, Suspense } from 'react';
import { Navigate, Outlet, Route, Routes } from 'react-router-dom';
import { DashboardLayout } from '@/shared/ui/layout';
import { ProtectedRoute } from '@/routes/ProtectedRoute';
import { PublicRoute } from '@/routes/PublicRoute';
import { RequireEntitlement } from '@/routes/RequireEntitlement';
import { RequireProduct } from '@/routes/RequireProduct';
import { RequireRoleAtTier } from '@/routes/RequireRoleAtTier';
import { Product, Tier } from '@/shared/types';
import { RootRoute } from '@/routes/RootRoute';
import { LEGACY_DEMO_REDIRECTS } from '@/shared/config/demoUrls';
import { CHANGE_PASSWORD_PATH } from '@/shared/constants/routeConstants';
import {
  Role,
  SUPER_ADMIN_ONLY,
  ADMIN_ONLY,
  STAFF_ROLES,
  CL_SALES_ROLES,
  CL_ACTIVITY_NOTES_ROLES,
  CL_MILEAGE_ROLES,
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
  HL_FIELD_ROLES,
  HL_MARKETING_ROLES,
  HL_CLINICAL_ROLES,
  HL_MANAGEMENT_ROLES,
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
const MyProfilePage = lazy(() =>
  import('@/modules/settings').then((m) => ({ default: m.MyProfilePage })),
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
// DEPRECATED — NOT NEEDED, PENDING REMOVAL. The three Grants modules
// (Funding / Applications / Agreements) were removed from the sidebar AND from
// the UI entirely on 2026-08-06 per the product owner, and are slated to be
// removed/purged from FE and BE. Their lazy imports and routes are commented
// out — not just nav-hidden — so /funding, /applications and /agreements are
// unreachable even by typing the URL. The module code is left on disk only so
// the section can be restored quickly if it turns out to be needed; uncomment
// these three imports and their routes below to do that.
// const FundingPage = lazy(() =>
//   import('@/modules/funding').then((m) => ({ default: m.FundingPage })),
// );
// const ApplicationsPage = lazy(() =>
//   import('@/modules/applications').then((m) => ({ default: m.ApplicationsPage })),
// );
// const AgreementsPage = lazy(() =>
//   import('@/modules/agreements').then((m) => ({ default: m.AgreementsPage })),
// );
const LocationsPage = lazy(() =>
  import('@/modules/locations').then((m) => ({ default: m.LocationsPage })),
);
const TerritoriesEntityPage = lazy(() =>
  import('@/modules/territories').then((m) => ({ default: m.TerritoriesPage })),
);
// HIDDEN (intentionally): Training providers module hidden from the frontend by
// request. Route + lazy import commented out so the page is not reachable even
// by direct URL. Do NOT re-enable without confirming with the product owner.
// const TrainingProvidersPage = lazy(() =>
//   import('@/modules/training-providers').then((m) => ({
//     default: m.TrainingProvidersPage,
//   })),
// );
const DocumentsPage = lazy(() =>
  import('@/modules/documents').then((m) => ({ default: m.DocumentsPage })),
);
const DataImportExportPage = lazy(() =>
  import('@/modules/admin').then((m) => ({ default: m.DataImportExportPage })),
);

// --- HospiceLink screens --------------------------------------------------

// Aliased: @/modules/cl-leads also exports a LeadsPage (CommunityLink resident
// leads). These are different products' intake screens and must not be conflated.
const HlLeadsPage = lazy(() =>
  import('@/modules/leads').then((m) => ({ default: m.LeadsPage })),
);
const JobsPage = lazy(() =>
  import('@/modules/jobs').then((m) => ({ default: m.JobsPage })),
);
const AppointmentsPage = lazy(() =>
  import('@/modules/appointments').then((m) => ({ default: m.AppointmentsPage })),
);
const PublicReferralFormPage = lazy(() =>
  import('@/modules/referral-portal').then((m) => ({
    default: m.PublicReferralFormPage,
  })),
);
const TerritoryPlannerPage = lazy(() =>
  import('@/modules/territories').then((m) => ({
    default: m.TerritoryPlannerPage,
  })),
);
const ReferralPortalPage = lazy(() =>
  import('@/modules/referral-portal').then((m) => ({
    default: m.ReferralPortalPage,
  })),
);
const ReengagementPage = lazy(() =>
  import('@/modules/prospects').then((m) => ({ default: m.ReengagementPage })),
);
const MarketerLeaderboardPage = lazy(() =>
  import('@/modules/intelligence').then((m) => ({
    default: m.MarketerLeaderboardPage,
  })),
);
const AutomationPage = lazy(() =>
  import('@/modules/automation').then((m) => ({ default: m.AutomationPage })),
);
const DailyQueuePage = lazy(() =>
  import('@/modules/daily-queue').then((m) => ({ default: m.DailyQueuePage })),
);
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
  import('@/modules/scheduling').then((m) => ({ default: m.NurseRosterPage })),
);
const ActivityPage = lazy(() =>
  import('@/modules/activity').then((m) => ({ default: m.ActivityPage })),
);
const PlaybookGeneratorPage = lazy(() =>
  import('@/modules/ai-assistant').then((m) => ({
    default: m.PlaybookGeneratorPage,
  })),
);
const AiAssistantPage = lazy(() =>
  import('@/modules/ai-assistant').then((m) => ({ default: m.AiAssistantPage })),
);
const ClinicalPage = lazy(() =>
  import('@/modules/clinical').then((m) => ({ default: m.ClinicalPage })),
);
const ReferralScorecardPage = lazy(() =>
  import('@/modules/intelligence').then((m) => ({ default: m.ReferralScorecardPage })),
);
const WeeklyReportPage = lazy(() =>
  import('@/modules/intelligence').then((m) => ({ default: m.WeeklyReportPage })),
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

const HospiceContactsPage = lazy(() =>
  import('@/modules/hospice-contacts').then((m) => ({
    default: m.HospiceContactsPage,
  })),
);
const EvvPage = lazy(() =>
  import('@/modules/field').then((m) => ({ default: m.EvvPage })),
);
const MileagePage = lazy(() =>
  import('@/modules/field').then((m) => ({ default: m.MileagePage })),
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
// The CommunityLink shared team calendar and self-assembling morning list. Both
// are CommunityLink's own screens over cl/* data — see each module's barrel for
// why HospiceLink's /appointments and /daily-tasks could not be reused.
const ClCalendarPage = lazy(() =>
  import('@/modules/cl-calendar').then((m) => ({ default: m.ClCalendarPage })),
);
const ClDailyTaskPage = lazy(() =>
  import('@/modules/cl-daily-task').then((m) => ({ default: m.ClDailyTaskPage })),
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
        {/* The facility referral portal. Fully public and OUTSIDE the
            authenticated shell — the people who open this have no account, and
            wrapping it in PublicRoute (which redirects a signed-in user to the
            dashboard) would break it for a hospice admin testing their own QR
            code. The token in the path is the only authorisation. */}
        <Route
          path="/refer/:token"
          element={<PublicReferralFormPage />}
        />
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

        {/*
          The FORCED password change, and the one screen an admin-issued password
          can open. Deliberately a sibling of the dashboard shell rather than a
          child of it, for two reasons:

            1. ProtectedRoute redirects a pending user here. Inside the shell that
               would be a route redirecting to itself.
            2. Everything in the shell — sidebar counts, notification bell, every
               page widget — would fire requests the backend answers with 403
               PASSWORD_CHANGE_REQUIRED. The user would meet a broken dashboard
               instead of the one form they need.

          ChangePasswordPage is already an AuthCardShell standalone card, so it
          wants no dashboard chrome anyway. `allowPasswordChangePending` is the
          exemption that stops the redirect looping; it still requires a session.
        */}
        <Route
          path={CHANGE_PASSWORD_PATH}
          element={
            <ProtectedRoute allowPasswordChangePending>
              <ChangePasswordPage />
            </ProtectedRoute>
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
          {/* HospiceLink — product-gated as a group. A tenant without a
              HospiceLink entitlement is redirected home; the backend also 403s
              the clinical endpoints (defense in depth). Deep-linking here aligns
              the active dashboard to HospiceLink. */}
          <Route
            element={
              <RequireProduct product={Product.HospiceLink}>
                <Outlet />
              </RequireProduct>
            }
          >
          {/* Marketing group — HL_MARKETING_ROLES. These eight routes carried NO
              role guard at all: navigationConfig has hidden them from Nurse and
              Caregiver since the role groups landed, but a hidden nav item is
              not access control and typing the URL rendered the page. Grouped
              rather than repeated per route so a new marketing screen inherits
              the gate instead of having to remember it. `allow` mirrors
              navigationConfig's HL_MARKETING_ROLES exactly, and the matching
              backend @Roles now answers 403 — change one side, change all
              three. Appointments is deliberately NOT in here: it is an
              HL_FIELD_ROLES surface that Nurse and Caregiver do work in. Nor is
              Daily tasks (below, on its own field-roles gate) — the nurse and
              caregiver guides both open the day on it. */}
          {/* The personal work queue: every persona's morning screen, so it sits
              on HL_FIELD_ROLES rather than inside the marketing group. Server-side
              the queue is self-scoped (no userId parameter at all), which is what
              makes admitting the clinical roles safe. */}
          <Route
            path="daily-tasks"
            element={
              <ProtectedRoute allow={HL_FIELD_ROLES}>
                <DailyQueuePage />
              </ProtectedRoute>
            }
          />
          <Route
            element={
              <ProtectedRoute allow={HL_MARKETING_ROLES}>
                <Outlet />
              </ProtectedRoute>
            }
          >
            <Route path="automation" element={<AutomationPage />} />
            <Route path="re-engagement" element={<ReengagementPage />} />
            {/* The MARKETER-facing leaderboard: no revenue. Distinct from
                /intelligence/leaderboard, which is the Gold, admin-only report. */}
            <Route path="leaderboard" element={<MarketerLeaderboardPage />} />
            <Route path="hl-leads" element={<HlLeadsPage />} />
            <Route path="prospects" element={<ProspectsPage />} />
            <Route path="referrals" element={<ReferralsPage />} />
            <Route path="hl-contacts" element={<HospiceContactsPage />} />
            <Route path="referral-portal" element={<ReferralPortalPage />} />
            <Route path="pipeline" element={<PipelinePage />} />
            <Route path="jobs" element={<JobsPage />} />
            <Route path="territories" element={<TerritoriesEntityPage />} />
            <Route path="territory-planner" element={<TerritoryPlannerPage />} />
          </Route>
          {/* Activity group — HL_FIELD_ROLES. These six carried no role guard at
              all while navigationConfig's HOSPICELINK_ACTIVITY has gated every one
              of them to HL_FIELD_ROLES, so a CommunityLink-only persona or any
              future non-field HospiceLink role that typed the URL rendered the
              page. Grouped rather than repeated per route for the same reason the
              marketing and compliance groups are: a new Activity screen inherits
              the gate instead of having to remember it. HL_FIELD_ROLES (not
              HL_MARKETING_ROLES) is the point — Nurse and Caregiver log their
              visits, notes and goals here, and these screens plus Clinical are
              their workspace. `allow` mirrors navigationConfig exactly; change one
              side, change both. */}
          <Route
            element={
              <ProtectedRoute allow={HL_FIELD_ROLES}>
                <Outlet />
              </ProtectedRoute>
            }
          >
            <Route path="appointments" element={<AppointmentsPage />} />
            <Route path="activity/calendar" element={<ActivityPage />} />
            <Route path="activity/notes" element={<ActivityPage />} />
            <Route path="activity/reminders" element={<ActivityPage />} />
            <Route path="activity/goals" element={<ActivityPage />} />
            <Route path="activity/ai" element={<AiAssistantPage />} />
          </Route>

          {/* Premium HospiceLink modules. These were previously hidden by
              navigationConfig alone, which is not access control — typing the URL
              reached the page and the API served it (AUDIT-HOSPICELINK.md D-01).
              Each now carries the same route-level tier/role gate the
              CommunityLink block below has used all along, and the matching
              backend @RequireFeature answers 402 UPGRADE_REQUIRED. The minTier /
              allow values mirror navigationConfig exactly — change one side, change
              both. */}

          {/* Clinical — Gold + HL_CLINICAL_ROLES. These three carried the tier gate
              only, on the since-falsified premise that the nav showed Clinical to
              every role: navigationConfig's HOSPICELINK_CLINICAL gates all three to
              HL_CLINICAL_ROLES (management + Nurse + Caregiver), so the sidebar
              already hid Family communication from a Marketer or Rep while typing
              the URL still rendered it. That is a patient/family PHI surface, and a
              hidden nav item is not access control — the tier gate alone let every
              role on a Gold tenant in. `allow` now mirrors the nav exactly; change
              one side, change both. Marketing personas are deliberately excluded:
              their view of a patient stops at the referral, not the care. */}
          {/* Max, not Gold, and deliberately out of step with the two routes below:
              HospiceLink ranks Pro < Max < Gold, so this admits Max AND Gold. The
              family log is the record a nurse is required to keep, not an upsell —
              see the nav entry for the full argument. Change one side, change both. */}
          <Route path="clinical/family" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={HL_CLINICAL_ROLES}><ClinicalPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="clinical/messaging" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={HL_CLINICAL_ROLES}><ClinicalPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="clinical/admissions" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={HL_CLINICAL_ROLES}><ClinicalPage /></ProtectedRoute></RequireEntitlement>} />

          {/* Intelligence — Gold + staff. */}
          <Route path="intelligence/revenue" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={STAFF_ROLES}><IntelligencePage /></ProtectedRoute></RequireEntitlement>} />
          {/* Aliases of intelligence/revenue, kept so existing bookmarks resolve.
              Deliberately NOT in the sidebar: all three reports live on the one
              screen, so separate rows pointed at an identical view. Same guards as
              the row that is navigable. */}
          <Route path="intelligence/marketing-roi" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={STAFF_ROLES}><IntelligencePage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="intelligence/leaderboard" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={STAFF_ROLES}><IntelligencePage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="intelligence/weekly" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={STAFF_ROLES}><WeeklyReportPage /></ProtectedRoute></RequireEntitlement>} />
          <Route
            path="intelligence/referral-scorecard"
            element={
              <RequireEntitlement minTier={Tier.Gold}>
                <ProtectedRoute allow={STAFF_ROLES}>
                  <ReferralScorecardPage />
                </ProtectedRoute>
              </RequireEntitlement>
            }
          />

          {/* Field execution — Max. EVV and mileage had endpoints (and, for EVV,
              written RTK hooks) but no nav entry and no route, so both were
              unreachable while being sold at Max. `allow` mirrors the nav's
              HL_FIELD_ROLES so Nurse and Caregiver reach them — these two screens
              plus Notes and Family communication ARE the caregiver's workspace. */}
          <Route path="field/evv" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={HL_FIELD_ROLES}><EvvPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="field/mileage" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={HL_FIELD_ROLES}><MileagePage /></ProtectedRoute></RequireEntitlement>} />

          {/* Nurse scheduling (the roster) — Gold + HL_MANAGEMENT_ROLES. This is
              the ADMIN view of who is on shift, not a nurse's own diary, and
              nurse-scheduling.controller.ts gates every write (@Post/@Patch/
              @Delete) to Admin/Owner/Manager — so a Nurse or Caregiver let in here
              got a read-only roster of the whole team, which is neither useful to
              them nor theirs to see. `allow` mirrors the nav item's
              HL_MANAGEMENT_ROLES, which in turn mirrors that backend @Roles list;
              change one, change all three. The nurse's own-schedule view is the
              separate `comingSoon` "My visit schedule" row in the Clinical group. */}
          <Route path="scheduling" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={HL_MANAGEMENT_ROLES}><SchedulingPage /></ProtectedRoute></RequireEntitlement>} />

          {/* Integrations. Data import is every tier; Aircall is Gold; the
              Playbook generator is MAX, not Gold — do not "align" these three
              TIERS. The role gates are a separate axis and each has its own reason
              below. */}
          {/* Import/export — STAFF_ROLES, no tier gate. The screen had no guard at
              all, so any role could type the URL and reach a bulk data mover.
              data-transfer.controller.ts is @RequirePermission("import_export"),
              which the default permission matrix denies to Caregiver outright, and
              the end-user guide files Import Data under Admin/Office Manager — so
              STAFF_ROLES is the frontend mirror of that backend permission.
              DataImportExportPage serves BOTH halves and this route is the only way
              in to the EXPORT screen too; bulk export of the tenant's book of
              business is if anything the more sensitive half, so STAFF_ROLES is
              correct for both and must not be widened "because export is harmless".
              Mirrors the nav item; change one side, change both. */}
          <Route path="integrations/import" element={<ProtectedRoute allow={STAFF_ROLES}><DataImportExportPage /></ProtectedRoute>} />
          {/* Aircall — Gold + HL_MARKETING_ROLES. A phone console over the call and
              text history of referral accounts: outbound dialling and that history
              belong to the people who own those relationships, so it sits with the
              marketing group rather than with the field roles. Route and nav item
              were both ungated by role; both now carry this list. */}
          <Route path="integrations/aircall" element={<RequireEntitlement minTier={Tier.Gold}><ProtectedRoute allow={HL_MARKETING_ROLES}><IntegrationsPage /></ProtectedRoute></RequireEntitlement>} />
          {/* Was rendering IntegrationsPage — the nav item and the
              `playbook_generator` tier key existed with nothing behind them.
              Now the real screen; the backend gates the same key at Max. */}
          <Route path="integrations/playbooks" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={HL_MARKETING_ROLES}><PlaybookGeneratorPage /></ProtectedRoute></RequireEntitlement>} />

          {/* Compliance — Gold + admin. Covers the three nav entries plus the
              sub-screens (access review, DR test, breach, evidence, BAA records)
              that hang off the same group and were equally unguarded. */}
          <Route
            element={
              <RequireEntitlement minTier={Tier.Gold}>
                <ProtectedRoute allow={ADMIN_ONLY}>
                  <Outlet />
                </ProtectedRoute>
              </RequireEntitlement>
            }
          >
            {/* NOTE: there is deliberately no bare `compliance` route here. The
                public marketing /compliance page above claims that path, and a
                duplicate declared later never matches — it looked like a working
                route while silently sending signed-in admins to the marketing
                site. The sidebar points at /compliance/readiness. */}
            <Route path="compliance/readiness" element={<ReadinessPage />} />
            <Route path="compliance/audit" element={<CompliancePage />} />
            <Route path="compliance/access-review" element={<AccessReviewPage />} />
            <Route path="compliance/dr-test" element={<DrTestPage />} />
            <Route path="compliance/breach" element={<BreachWorkflowPage />} />
            <Route path="compliance/evidence" element={<EvidenceExportPage />} />
            <Route path="compliance/baa-records" element={<BaaRecordsPage />} />
            <Route path="compliance/threat-monitor" element={<ThreatMonitorPage />} />
          </Route>
          </Route>

          {/* CommunityLink — product-gated as a group (same isolation as the
              HospiceLink block: redirect home if not entitled, backend 403s the
              cl/* endpoints, deep-link aligns the active dashboard). */}
          <Route
            element={
              <RequireProduct product={Product.CommunityLink}>
                <Outlet />
              </RequireProduct>
            }
          >
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
          {/* The shared team calendar. `cl-calendar`, not `calendar`/`appointments`:
              HospiceLink's Calendar owns /appointments, and a duplicate path
              declared in a second product group would resolve to whichever came
              first for EVERY user (see the alert-settings note below). Mirrors the
              nav item's CL_SALES_ROLES — change one side, change both. */}
          <Route path="cl-calendar" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClCalendarPage /></ProtectedRoute>} />
          {/* Same prefixing reason: /daily-tasks is HospiceLink's daily queue. */}
          <Route path="cl-daily-task" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClDailyTaskPage /></ProtectedRoute>} />
          <Route path="ai-assistant" element={<ProtectedRoute allow={CL_SALES_ROLES}><AiAssistantPage /></ProtectedRoute>} />
          {/* CL_ACTIVITY_NOTES_ROLES — the sales roles plus Nurse/Caregiver, whom the
              guide points here as the stand-in for the unbuilt Resident Care Log.
              Mirrors the Care nav section; change one side, change both. */}
          <Route path="activity-notes" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_ACTIVITY_NOTES_ROLES}><ActivityNotesPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="gift-gratuity" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_FIELD_ACTIVITY_ROLES}><GiftGratuityPage /></ProtectedRoute></RequireEntitlement>} />
          <Route path="aircall" element={<RequireEntitlement minTier={Tier.Max}><ProtectedRoute allow={CL_SALES_ROLES}><AircallPage /></ProtectedRoute></RequireEntitlement>} />
          {/* Tasks is visible/usable by every CommunityLink role, including
              the field roles — matches every role's sidebar in the demo. */}
          <Route path="tasks" element={<ProtectedRoute allow={CL_ALL_ROLES}><TasksPage /></ProtectedRoute>} />
          <Route path="outreach/checkin" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClOutreachPage /></ProtectedRoute>} />
          {/* CL_MILEAGE_ROLES, not CL_SALES_ROLES: the guide tells care staff to "log
              those trips in Mileage & Expenses the same way a Sales Marketer does".
              Only mileage widens — GPS check-in and the outreach log stay sales-only. */}
          <Route path="outreach/mileage" element={<ProtectedRoute allow={CL_MILEAGE_ROLES}><ClOutreachPage /></ProtectedRoute>} />
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
          {/* CL_SALES_ROLES, widened from CL_MANAGEMENT_ROLES to match the nav item:
              the guide lists Reports Center among the Sales Marketer's everyday
              tools ("your leads-by-source chart and your tour-to-move-in conversion
              rate"). Field roles are still excluded. */}
          <Route path="reports" element={<ProtectedRoute allow={CL_SALES_ROLES}><ClReportsPage /></ProtectedRoute>} />
          </Route>

          {/* Grant CRM — contacts & employer companies. Shared/back-office
              routes below are NOT product-gated (cross-product); they appear
              only in the HospiceLink nav today but remain reachable to keep the
              back-office shared, matching the ungated backend endpoints. */}
          <Route path="contacts" element={<ContactsPage />} />
          <Route path="companies" element={<CompaniesPage />} />

          {/* Phase 4 domain modules */}
          <Route path="invoices" element={<InvoicesPage />} />
          <Route path="contracts" element={<ContractsPage />} />
          <Route path="finance" element={<FinanceOverviewPage />} />
          {/* DEPRECATED Grants routes — NOT NEEDED, PENDING REMOVAL. Disabled
              outright (not merely nav-hidden) per the product owner: the Grants
              domain is gone from the UI, so these three paths now fall through
              to the `path="*"` catch-all and redirect to the dashboard. See
              navigationConfig's commented-out GRANTS_SECTION. Do NOT re-enable without
              product-owner sign-off; to be removed/purged with the modules. */}
          {/* <Route path="funding" element={<FundingPage />} /> */}
          {/* <Route path="applications" element={<ApplicationsPage />} /> */}
          {/* <Route path="agreements" element={<AgreementsPage />} /> */}
          <Route path="locations" element={<LocationsPage />} />
          <Route path="territories-list" element={<TerritoriesEntityPage />} />
          {/* HIDDEN (intentionally): Training providers route disabled by request. Do NOT re-enable without product-owner sign-off. */}
          {/* <Route path="training-providers" element={<TrainingProvidersPage />} /> */}
          {/* /<Route path="training-providers" element={<TrainingProvidersPage />} /> */}
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
          {/* Personal profile — deliberately NO role gate. Every authenticated
              role must be able to edit their own name and calendar colour;
              /settings above stays ADMIN_ONLY because it edits the org. */}
          <Route path="my-profile" element={<MyProfilePage />} />
          {/*
            Alert settings is CROSS-PRODUCT: the backend route carries no
            @RequireProduct, and the screen now takes its alert vocabulary from
            the server, which scopes it to the products the tenant holds. It
            moved out of the CommunityLink group so a HospiceLink admin can reach
            it at the same URL — two routes with the same path in two product
            groups would have made the first one win for everybody.

            The tier differs by product because the two ladders are inverted:
            this capability sits at the TOP tier of each (HL Gold, CL Max), which
            is rank 3 on both and matches the backend's single `alert_settings`
            feature key.
          */}
          {/*
            Financial settings is cross-product for the same reason as
            alert-settings: the backend controller carries no @RequireProduct (it
            lives in src/mileage and is keyed by setting name, not product), and
            HospiceLink now needs it — Revenue Intelligence's cost-per-admission
            is driven by the `marketing_spend_monthly` value recorded here, and
            its "Record it in financial settings" call to action pointed at a
            route only CommunityLink could reach.
          */}
          <Route
            path="financial-settings"
            element={
              <RequireEntitlement
                minTier={{
                  [Product.HospiceLink]: Tier.Gold,
                  [Product.CommunityLink]: Tier.Max,
                }}
              >
                <ProtectedRoute allow={ADMIN_ONLY}>
                  <FinancialSettingsPage />
                </ProtectedRoute>
              </RequireEntitlement>
            }
          />
          <Route
            path="alert-settings"
            element={
              <RequireEntitlement
                minTier={{
                  [Product.HospiceLink]: Tier.Gold,
                  [Product.CommunityLink]: Tier.Max,
                }}
              >
                <ProtectedRoute allow={ADMIN_ONLY}>
                  <AlertSettingsPage />
                </ProtectedRoute>
              </RequireEntitlement>
            }
          />
          <Route path="settings" element={<ProtectedRoute allow={ADMIN_ONLY}><SettingsPage /></ProtectedRoute>} />
          {/* The VOLUNTARY change, reached from settings, so it keeps the dashboard
              chrome around it. The forced one is /change-password, declared outside
              this shell — see the note there for why it cannot live in here. */}
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

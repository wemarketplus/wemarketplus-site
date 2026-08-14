import { Card, CardContent } from '@/shared/ui/core';
import { OnboardingChecklistCard } from '@/modules/onboarding-checklist';
import { useRole, ADMIN_ONLY, HL_MARKETING_ROLES, STAFF_ROLES } from '@/shared/rbac';
import { Product, Tier, tierIncludes } from '@/shared/types';
import { cn } from '@/shared/utils/cn';
import { MarketerDayPanel } from '../components/MarketerDayPanel';
import { DashboardActivityList } from '../components/DashboardActivityList';
import { DashboardPageHeader } from '../components/DashboardPageHeader';
import { DashboardStatTile } from '../components/DashboardStatTile';
import { OperationsAlertsCard } from '../components/OperationsAlertsCard';
import { PortfolioFinancialCard } from '../components/PortfolioFinancialCard';
import { PortfolioLeakageCard } from '../components/PortfolioLeakageCard';
import { PortfolioMaintenanceCard } from '../components/PortfolioMaintenanceCard';
import { PortfolioReferralPipelineCard } from '../components/PortfolioReferralPipelineCard';
import { UnitStatusCard } from '../components/UnitStatusCard';
import { useDashboardContext } from '../hooks/useDashboardContext';
import { useDashboardGreeting } from '../hooks/useDashboardGreeting';
import { useProductDashboard } from '../hooks/useProductDashboard';

export function DashboardPage() {
  const { greeting, name, role, title } = useDashboardGreeting();
  const {
    stats,
    activity,
    operations,
    portfolio,
    portfolioOperations,
    alerts,
    isLoading,
    isError,
  } = useProductDashboard();
  const { product, tier, organizationName, period, hasActivePlan } =
    useDashboardContext();

  /**
   * Whether the owner's financial card actions have somewhere to go.
   *
   * The Financial Ledger and Revenue Leakage routes carry
   * `RequireEntitlement minTier={Tier.Max}` (CommunityLink Max), which is the guide's
   * "on larger plans" in step 6. The NUMBERS on those cards ship at every tier —
   * step 1 promises them unconditionally — so only the buttons are gated. A button
   * that redirects to /billing is a worse answer than a card that simply states the
   * figure.
   */
  const canOpenFinancialModules = tierIncludes(
    Product.CommunityLink,
    tier,
    Tier.Max,
  );

  const { isAny } = useRole();
  // A HospiceLink field user opens the day on their OWN numbers: weekly pacing
  // and what needs them today. The tenant roll-up below stays for everyone.
  const showMarketerDay =
    product === Product.HospiceLink && isAny(HL_MARKETING_ROLES);
  // Overdue invoices is a Financial figure a field user cannot open, let alone
  // act on — the Financial group is staff-only. Showing it made a quarter of
  // their dashboard a dead number.
  const visibleStats = isAny(STAFF_ROLES)
    ? stats
    : stats.filter((stat) => stat.id !== 'overdue-invoices');
  /**
   * The getting-started checklist is WORKSPACE SETUP — invite the team, import
   * prospects, finish billing — so it belongs to whoever administers the tenant.
   *
   * Gated because it was not merely irrelevant to a field persona but broken for
   * one: the checklist derives its steps from the prospects, users and tenant
   * lists, all of which answer 403 to a Nurse or Caregiver. Their dashboard fired
   * three forbidden requests on every load and rendered a checklist of steps they
   * are not allowed to complete.
   */
  const showOnboardingChecklist = isAny(ADMIN_ONLY);

  return (
    <div className="space-y-8">
      <DashboardPageHeader
        greeting={greeting}
        name={name}
        role={role}
        title={title}
        product={product}
        tier={tier}
        organizationName={organizationName}
        period={period}
        hasActivePlan={hasActivePlan}
      />

      {showOnboardingChecklist && <OnboardingChecklistCard />}

      {showMarketerDay && <MarketerDayPanel />}

      {isError ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            We could not load your dashboard right now. Please try again in a
            moment.
          </CardContent>
        </Card>
      ) : isLoading ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading your dashboard…
          </CardContent>
        </Card>
      ) : (
        <>
          {/* The Executive and Portfolio dashboards are SIX-tile strips, so they
              wrap 3-up rather than 4-up — four across would leave two stranded on a
              second row. Keyed off the tile count itself rather than off
              `operations`, because the owner's six tiles render at every tier,
              including the ones where `operations` is absent. */}
          <div
            className={cn(
              'grid grid-cols-1 gap-4 sm:grid-cols-2',
              visibleStats.length === 6 ? 'lg:grid-cols-3' : 'lg:grid-cols-4',
            )}
          >
            {visibleStats.map((stat) => (
              <DashboardStatTile key={stat.id} stat={stat} />
            ))}
          </div>

          {/* Executive Director only: the at-a-glance breakdown beside the panel
              that says what to do about it. Both are driven by `operations`, which
              the server sends only when the plan includes the modules they link
              into — so neither can offer a route the viewer would be bounced from. */}
          {operations && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <UnitStatusCard operations={operations} />
              <OperationsAlertsCard alerts={alerts} />
            </div>
          )}

          {/* Owner/Investor only: the four cards the guide walks through in steps
              2–5, in that order. Driven by `portfolio`, which the server omits for
              any role outside CL_FINANCIAL_ROLES — so this block cannot render
              figures the viewer was never sent.

              Unit status rides along at the end when the plan includes operations:
              the reference design puts an "Operations Status" column on the owner's
              screen, and this is the same breakdown the executive gets, from the
              same server counts. Its Alerts sibling is deliberately not here — see
              PortfolioMaintenanceCard. */}
          {portfolio && (
            <>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <PortfolioFinancialCard
                  portfolio={portfolio}
                  operations={portfolioOperations}
                  canOpenLedger={canOpenFinancialModules}
                />
                <PortfolioLeakageCard
                  portfolio={portfolio}
                  canOpenLeakage={canOpenFinancialModules}
                />
              </div>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <PortfolioReferralPipelineCard portfolio={portfolio} />
                {portfolioOperations ? (
                  <PortfolioMaintenanceCard
                    operations={portfolioOperations}
                  />
                ) : null}
              </div>
              {portfolioOperations && (
                <UnitStatusCard operations={portfolioOperations} />
              )}
            </>
          )}

          <DashboardActivityList items={activity} />
        </>
      )}
    </div>
  );
}

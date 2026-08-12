import { Role, useRole } from '@/shared/rbac';
import { ClCareDashboard } from './ClCareDashboard';
import { ClExecutiveDashboard } from './ClExecutiveDashboard';
import { ClMyQueuePanel } from './ClMyQueuePanel';
import { ClPortfolioDashboard } from './ClPortfolioDashboard';
import { ClSalesDashboard } from './ClSalesDashboard';

/**
 * Picks the CommunityLink dashboard the signed-in role's guide describes.
 *
 * The guide gives each role a DIFFERENT home screen under a different name —
 * "Your Sales Dashboard shows Active Leads, Hot Leads, and Tours Scheduled",
 * "Your Executive Dashboard shows Occupancy %…", "Your Portfolio Dashboard gives
 * you the financial and occupancy picture", "Check My Queue first thing" — and
 * before this the product served one generic four-tile screen to all of them. A
 * maintenance tech opening the app met a lead-conversion figure they cannot act
 * on and no sign of their own tickets.
 *
 * The role→screen map is spelled out per role rather than derived from the
 * CL_* role groups. Those groups answer "may this role SEE module X", which is a
 * different question from "which of four home screens is this person's job", and
 * the two disagree: Sales/Admissions is in CL_FINANCIAL_ROLES but their morning
 * is the pipeline, not the rent roll. A switch that names each persona is also
 * what makes a missing case a visible fallback rather than a silent wrong screen.
 *
 * FALLBACK is the sales dashboard: every remaining CommunityLink role
 * (Manager, Marketer, Sales/Admissions, and any base role a custom role sits on)
 * works the pipeline. Field roles and the two oversight personas are the
 * exceptions, and they are the ones named.
 */
export function ClDashboardPanel() {
  const { role } = useRole();

  switch (role) {
    case Role.Maintenance:
    case Role.Housekeeping:
      return <ClMyQueuePanel role={role} />;
    // AL / Memory Care staff. Without this case they landed on the Sales
    // Dashboard and were shown lead-conversion figures that are not their job.
    case Role.Nurse:
    case Role.Caregiver:
      return <ClCareDashboard />;
    case Role.OwnerInvestor:
      return <ClPortfolioDashboard />;
    case Role.Director:
      return <ClExecutiveDashboard />;
    /**
     * Admin and Owner get the EXECUTIVE screen, not the portfolio one. Both can
     * reach every tab, so the question is what they should see first, and the Max
     * demo answers it: the Administrator's dashboard sits beside Occupancy
     * Overview in an operations-shaped group, while Owner/Investor's is the
     * financial roll-up. An administrator's day is the community running, not the
     * investor return.
     */
    case Role.SuperAdmin:
    case Role.Admin:
    case Role.Owner:
      return <ClExecutiveDashboard />;
    default:
      return <ClSalesDashboard />;
  }
}

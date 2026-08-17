import { useActiveEntitlement } from '@/modules/access';
import { useGetSeatUsageQuery } from '@/modules/users';
import { PRODUCT_LABELS, TIER_LABELS } from '@/shared/types';

/**
 * The Settings answer to "what plan am I on, and how many seats have I used?" —
 * step 3 of the Administrator's Account Settings flow.
 *
 * Two sources, deliberately, because they answer two different questions:
 *
 *  - `useActiveEntitlement` names the PLAN THIS DASHBOARD RUNS ON (CommunityLink
 *    Max). It reads the entitlement already in the auth store, so it costs no
 *    request, and it is per-product — which is the figure an admin looking at
 *    the CommunityLink Settings screen means by "my plan".
 *  - `GET /users/seats` counts SEATS, which are billed once per tenant against
 *    the subscription rather than per product. Its `planName` is therefore the
 *    BILLING plan and can legitimately differ from the label above on a
 *    dual-product tenant — see TeamOverviewStats, which surfaces the same pair
 *    on the Team page and says so for the same reason.
 *
 * `allowed`/`remaining` are nullable server-side: an unrecognised plan is treated
 * as uncapped, so null means "no cap known", never zero. `atLimit` is only true
 * when a cap is actually known and reached — the invite button must not be
 * disabled on a tenant whose plan simply has no seat rule.
 */
export function useAccountPlan() {
  const { product, tier, subscriptionStatus } = useActiveEntitlement();
  const { data: seats, isLoading, isError, refetch } = useGetSeatUsageQuery();

  const allowed = seats?.allowed ?? null;
  const remaining = seats?.remaining ?? null;

  return {
    /** e.g. "CommunityLink Max" — the active dashboard's own plan. */
    planLabel: `${PRODUCT_LABELS[product]} ${TIER_LABELS[tier]}`,
    /** The tenant-level billing plan behind the seat count, when the API names one. */
    billingPlanName: seats?.planName ?? null,
    /** Undefined for a dashboard the tenant holds no entitlement for. */
    subscriptionStatus,
    used: seats?.used ?? null,
    allowed,
    remaining,
    hasSeatLimit: allowed !== null,
    atLimit: remaining === 0,
    /** False in dev/test, where the limit is displayed but not enforced. */
    enforced: seats?.enforced ?? false,
    isLoading,
    isError,
    refetch,
  };
}

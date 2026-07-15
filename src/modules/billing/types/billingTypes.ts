import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import type {
  ID,
  ISODateString,
  Product,
  SubscriptionStatus,
  Tier,
} from '@/shared/types';

// Visual tone for billing alert cards. Shared by the alert config, the
// derived-alert hook, and the BillingAlert component.
export type AlertTone = 'warning' | 'destructive';

// Mirrors a ResolvedPlan from wemarketplus-backend/src/billing/plan-catalog.ts
// (returned by GET /billing/plans). One purchasable plan in the catalog.
export interface PlanOption {
  key: string;
  product: Product;
  tier: string;
  package: string;
  name: string;
  seats: number;
  price: string;
  priceId: string;
  // Gated feature keys unlocked by this tier (e.g. "ai_assistant"). Rendered
  // with friendly labels via PLAN_FEATURE_LABELS; unknown keys are skipped.
  features?: string[];
}

// Body for POST /billing/checkout — names the catalog plan to buy.
export interface CreateCheckoutRequest {
  planKey?: string;
}

// Body for POST /billing/checkout/confirm — server-side verification of the
// Stripe Checkout session on the success redirect (the query param alone is
// never trusted).
export interface ConfirmCheckoutRequest {
  sessionId: string;
}

// Body for POST /billing/change-plan/preview — names the target catalog plan.
export interface PreviewPlanChangeRequest {
  planKey: string;
}

// Mirrors wemarketplus-backend/src/billing/dto/plan-change-preview.dto.ts.
// The prorated amount + effective date shown before committing a plan change.
export interface PlanChangePreview {
  // Net amount due now, in the currency's minor unit (cents).
  amountDue: number;
  currency: string;
  // Unix timestamp (seconds) Stripe used for proration — echo it back verbatim
  // to POST /billing/change-plan so the applied charge matches the preview.
  prorationDate: number;
  currentPlanKey: string | null;
  newPlanKey: string;
  // True for an upgrade (applied and invoiced now); false for a downgrade
  // (scheduled for the end of the paid period, nothing due today).
  effectiveImmediately: boolean;
  // ISO timestamp the change takes effect (now for upgrades, period end for
  // downgrades).
  effectiveAt: string | null;
}

// Body for POST /billing/change-plan — the target plan plus the prorationDate
// echoed from the preview.
export interface ChangePlanRequest {
  planKey: string;
  prorationDate: number;
}

// Mirrors wemarketplus-backend/src/billing/dto/subscription-response.dto.ts.
export interface SubscriptionRecord {
  id: ID;
  tenantId: ID;
  stripeSubscriptionId: string | null;
  stripeCustomerId: string | null;
  plan: string;
  // Catalog resolution of `plan` attached by the backend when the price id
  // maps to a known plan. `tier` is the backend CrmTier (may be cl_-prefixed).
  planKey?: string;
  planName?: string;
  tier?: string;
  product?: Product;
  status: SubscriptionStatus;
  cancelAtPeriodEnd: boolean;
  currentPeriodEnd: ISODateString | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
  // Set by an upgrade that raised a proration invoice to pay: Stripe's hosted
  // invoice page. The client redirects here to collect payment.
  paymentUrl?: string;
}

// View-model the SubscriptionStatusPage renders. Derived from SubscriptionRecord
// plus auth context (the backend subscription has no product/org name fields).
export interface SubscriptionView {
  product: Product;
  plan: Tier;
  status: SubscriptionStatus;
  currentPeriodEnd: ISODateString;
  scheduledDeleteAt?: ISODateString;
  organizationName: string;
}

export interface AiUsageToday {
  count: number;
}

export interface BillingPortalResponse {
  url: string;
}

export interface BillingUiState {
  _placeholder: true;
}

// Static per-status alert config (icon/tone/title/action). The dynamic
// description is filled in by useSubscriptionAlert at runtime.
export interface SubscriptionAlertConfig {
  icon: LucideIcon;
  tone: AlertTone;
  title: string;
  actionLabel: string;
}

// A fully-resolved alert (config + runtime-derived description) for rendering.
export interface SubscriptionAlert extends SubscriptionAlertConfig {
  description: ReactNode;
}

// --- Component prop types ---

export interface PlanCardProps {
  product: Product;
  plan: Tier;
  organizationName: string;
}

export interface BillingAlertProps {
  icon: LucideIcon;
  tone: AlertTone;
  title: string;
  description: ReactNode;
  actionLabel: ReactNode;
  onAction: () => void;
  actionDisabled?: boolean;
}

export interface PlanPickerProps {
  plans: readonly PlanOption[];
  isLoading: boolean;
  busyPlanKey: string | null;
  onChoose: (planKey: string) => void;
}

export interface NoSubscriptionPanelProps {
  onGoToCrm: () => void;
}

export interface UpgradePanelProps {
  onGoToCrm: () => void;
  onManageBilling: () => void;
  manageDisabled?: boolean;
}

export interface SubscriptionSummaryProps {
  data: SubscriptionView;
}

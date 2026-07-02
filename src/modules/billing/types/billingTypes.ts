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

// Mirrors wemarketplus-backend/src/billing/dto/subscription-response.dto.ts.
export interface SubscriptionRecord {
  id: ID;
  tenantId: ID;
  stripeSubscriptionId: string | null;
  stripeCustomerId: string | null;
  plan: string;
  status: SubscriptionStatus;
  cancelAtPeriodEnd: boolean;
  currentPeriodEnd: ISODateString | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
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

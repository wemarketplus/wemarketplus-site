import type {
  ISODateString,
  Product,
  SubscriptionStatus,
  Tier,
} from '@/shared/types';

// Mirrors what wemarketplus-site/subscription-status.html renders.
export interface SubscriptionRecord {
  product: Product;
  plan: Tier;
  status: SubscriptionStatus;
  currentPeriodEnd: ISODateString;
  scheduledDeleteAt?: ISODateString;
  organizationName: string;
}

export interface BillingPortalResponse {
  url: string;
}

export interface BillingUiState {
  _placeholder: true;
}

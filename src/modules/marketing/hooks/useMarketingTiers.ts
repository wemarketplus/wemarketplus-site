import { Product } from '@/shared/types';
import {
  COMMUNITYLINK_TIERS,
  HOSPICELINK_TIERS,
} from '../constants/marketingConstants';

export function useMarketingTiers(product: Product) {
  return product === Product.CommunityLink
    ? COMMUNITYLINK_TIERS
    : HOSPICELINK_TIERS;
}

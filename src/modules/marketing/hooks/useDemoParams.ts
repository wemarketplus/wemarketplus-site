import { useParams } from 'react-router-dom';
import { Product, Tier } from '@/shared/types';

// Parses /demo/:product/:tier with sensible defaults so a typo'd URL still
// renders something instead of throwing.
export function useDemoParams(): { product: Product; tier: Tier } {
  const params = useParams<{ product?: string; tier?: string }>();
  const product =
    params.product === 'communitylink' ? Product.CommunityLink : Product.HospiceLink;
  const tier =
    params.tier === 'gold'
      ? Tier.Gold
      : params.tier === 'max'
      ? Tier.Max
      : Tier.Pro;
  return { product, tier };
}

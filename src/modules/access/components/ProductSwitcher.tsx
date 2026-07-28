import { useNavigate } from 'react-router-dom';
import { Product, PRODUCT_LABELS } from '@/shared/types';
import { cn } from '@/shared/utils/cn';
import { useActiveProduct } from '../hooks/useActiveProduct';
import { useEntitlements } from '../hooks/useEntitlements';

/**
 * Segmented control in the sidebar brand block that switches the active
 * dashboard between the products the user is entitled to. Renders nothing for
 * single-product users, so it only appears when a switch is actually possible.
 *
 * Switching lands the user on `/` (the shared dashboard home, which renders the
 * newly-active product) rather than leaving them on a route that may not exist —
 * or be authorized — for the other product.
 */
export function ProductSwitcher() {
  const navigate = useNavigate();
  const { products, hasMultiple } = useEntitlements();
  const { activeProduct, changeProduct } = useActiveProduct();

  if (!hasMultiple) return null;

  const onSelect = (product: Product) => {
    if (product === activeProduct) return;
    changeProduct(product);
    navigate('/', { replace: true });
  };

  return (
    <div
      role="group"
      aria-label="Switch dashboard"
      className="mt-2.5 flex gap-1 rounded-[8px] bg-foreground/[0.05] p-0.5"
    >
      {products.map((product) => {
        const isActive = product === activeProduct;
        const isCommunity = product === Product.CommunityLink;
        return (
          <button
            key={product}
            type="button"
            onClick={() => onSelect(product)}
            aria-pressed={isActive}
            title={PRODUCT_LABELS[product]}
            className={cn(
              'flex-1 truncate rounded-[8px] px-2 py-1 text-[10px] font-bold uppercase tracking-[0.06em] transition-colors',
              isActive
                  // One accent for both products — the switcher marks which
                  // dashboard is active, it does not rebrand the console.
                ? 'bg-primary text-primary-foreground'
                : 'text-muted hover:text-foreground',
            )}
          >
            {isCommunity ? 'Community' : 'Hospice'}
          </button>
        );
      })}
    </div>
  );
}

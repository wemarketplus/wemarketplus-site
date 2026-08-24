import { useEffect, useRef, useState } from 'react';
import { Check, ChevronDown } from 'lucide-react';
import { Product, PRODUCT_LABELS } from '@/shared/types';
import {
  HEADER_CONTROL_BASE,
  HEADER_CONTROL_HEIGHT,
} from '@/shared/ui/core/controlStyles';
import { cn } from '@/shared/utils/cn';
import { useActiveProduct } from '../hooks/useActiveProduct';
import { useEntitlements } from '../hooks/useEntitlements';

/**
 * The active-product control in the topbar, beside the notifications bell.
 *
 * Shows ONLY the product currently in use. It was previously a segmented
 * control in the sidebar showing both products side by side, which read as two
 * things being simultaneously on — the console is only ever rendering one
 * dashboard, and the chrome should say which. A menu makes the current state
 * unambiguous and the switch an explicit act.
 *
 * Lists BOTH dashboards for EVERY authenticated user, whatever their role and
 * whatever the tenant is billed for. It previously rendered nothing unless the
 * tenant held two entitlements, so most users never saw it — dashboard access
 * and billing entitlement are different questions (see productAccess.ts).
 *
 * Renders nothing when there is no session: no user, no dashboards to switch.
 */
export function ProductSwitcher() {
  const { products } = useEntitlements();
  const { activeProduct, changeProduct } = useActiveProduct();

  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close on outside click and on Escape. `mousedown` rather than `click` so the
  // menu is gone before a click lands on whatever is underneath it.
  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      setOpen(false);
      // Return focus to the trigger, or the user is left with nothing focused.
      buttonRef.current?.focus();
    };
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (products.length === 0) return null;

  const onSelect = (product: Product) => {
    setOpen(false);
    if (product === activeProduct) return;
    /**
     * Changing the active product is the WHOLE switch. Nothing here touches the
     * session: no token is cleared, no request is re-issued, no navigation to
     * /login. `setActiveProduct` is a single reducer on the access slice, and
     * the user stays exactly as authenticated as they were a moment ago.
     *
     * Deliberately NO navigate(). This used to unconditionally send the user to
     * `/`, which meant switching from /my-profile — a page both dashboards
     * share — kicked you back to the home screen for no reason. Product-scoped
     * routes still leave, but that is decided by RequireProduct, which is the
     * thing that actually knows a route belongs to one product. Shared routes
     * have no such guard, so the user keeps their place.
     */
    changeProduct(product);
  };

  const shortLabel = (product: Product) =>
    product === Product.CommunityLink ? 'Community' : 'Hospice';

  return (
    <div ref={rootRef} className="relative">
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Active dashboard: ${PRODUCT_LABELS[activeProduct]}. Change dashboard`}
        // Geometry, hairline and surface from HEADER_CONTROL_* so this control,
        // the search pill, the bell and the profile chip either side of it are
        // provably the same object. It was `py-1` with its own copy of the
        // border, which made it both the shortest control in the row and a
        // second spelling of the row's hairline.
        className={cn(
          HEADER_CONTROL_BASE,
          HEADER_CONTROL_HEIGHT,
          'flex items-center gap-2 pl-3 pr-2',
          open && 'border-primary/40 bg-primary/[0.06]',
        )}
      >
        {/* A filled dot reads as "this one is live" at a glance, before the
            label is read. One accent for both products — the control marks
            which dashboard is active, it does not rebrand the console. */}
        <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden="true" />
        <span className="text-xs font-semibold leading-none text-foreground">
          {shortLabel(activeProduct)}
        </span>
        <ChevronDown
          className={cn(
            'h-3.5 w-3.5 text-muted-soft transition-transform',
            open && 'rotate-180',
          )}
          aria-hidden="true"
        />
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Switch dashboard"
          className={cn(
            'absolute right-0 z-50 mt-2 w-56 overflow-hidden rounded-lg',
            'border border-border/[0.1] bg-surface shadow-2xl',
          )}
        >
          <p className="px-3 pt-2.5 pb-1 text-[10px] uppercase tracking-label text-muted-soft">
            Dashboard
          </p>
          {products.map((product) => {
            const isActive = product === activeProduct;
            return (
              <button
                key={product}
                type="button"
                role="menuitemradio"
                aria-checked={isActive}
                onClick={() => onSelect(product)}
                className={cn(
                  'flex w-full items-center gap-2.5 px-3 py-2.5 text-left transition-colors',
                  // Both rows keep a visible hover. The active row previously
                  // carried a tint that its hover could not overcome, so it read
                  // as a disabled/selected state rather than a live choice —
                  // which is exactly how a switcher should NOT feel.
                  isActive
                    ? 'bg-primary/[0.06] hover:bg-primary/[0.12]'
                    : 'hover:bg-foreground/[0.06]',
                )}
              >
                {/* Filled dot = the dashboard you are in; hollow ring = the one
                    you can move to. The ring is drawn in the SAME accent as the
                    filled dot, never a muted grey: an earlier version greyed the
                    inactive row out and it was read as "that option is
                    disabled", which is the one impression this control must not
                    give. Both rows are real buttons at all times. */}
                <span
                  className={cn(
                    'h-1.5 w-1.5 shrink-0 rounded-full',
                    isActive
                      ? 'bg-primary'
                      : 'border border-primary/70 bg-transparent',
                  )}
                  aria-hidden="true"
                />
                <span
                  className={cn(
                    'min-w-0 flex-1 truncate text-xs leading-none text-foreground',
                    isActive ? 'font-semibold' : 'font-medium',
                  )}
                >
                  {PRODUCT_LABELS[product]}
                </span>
                {isActive && (
                  <Check className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

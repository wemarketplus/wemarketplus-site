import { useCallback, useState, type ReactNode, type Ref } from 'react';
import { createPortal } from 'react-dom';
import { useAnchoredPopover } from '@/shared/hooks/useAnchoredPopover';
import { cn } from '@/shared/utils/cn';

interface DropdownMenuProps {
  /** The control that opens the menu — usually an icon button. */
  trigger: (props: {
    ref: Ref<HTMLButtonElement>;
    onClick: () => void;
    'aria-haspopup': 'menu';
    'aria-expanded': boolean;
  }) => ReactNode;
  /** Menu contents. Called with `close` so an item can dismiss the menu. */
  children: (close: () => void) => ReactNode;
  /** Menu width in px. Default 208 (w-52), matching the users table menu. */
  width?: number;
}

/**
 * A row/toolbar dropdown that is never clipped by its container.
 *
 * The users ("Team") table's kebab menu used to be an `absolute` div inside the
 * row's cell, which DataTable's `overflow-hidden` corner-clipping wrapper cut off
 * on the lower rows — the menu opened, but into invisible space, so clicking the
 * kebab looked like nothing happened. This renders through a portal and is placed
 * in viewport coordinates instead; see useAnchoredPopover for why that is the
 * only thing that works and how flipping/clamping is decided.
 */
export function DropdownMenu({ trigger, children, width = 208 }: DropdownMenuProps) {
  const [open, setOpen] = useState(false);
  // Stable identity: useAnchoredPopover re-binds its listeners when this changes.
  const close = useCallback(() => setOpen(false), []);

  const { anchorRef, panelRef, position } = useAnchoredPopover<
    HTMLButtonElement,
    HTMLDivElement
  >({ open, onClose: close, width, align: 'end' });

  return (
    <>
      {trigger({
        ref: anchorRef,
        onClick: () => setOpen((v) => !v),
        'aria-haspopup': 'menu',
        'aria-expanded': open,
      })}
      {open &&
        createPortal(
          <div
            ref={panelRef}
            role="menu"
            style={{
              top: position?.top ?? 0,
              left: position?.left ?? 0,
              width,
              // Hidden until measured, so the first paint is never at 0,0.
              visibility: position ? 'visible' : 'hidden',
              /**
               * The menu can never be taller than the viewport it is clamped to.
               *
               * useAnchoredPopover flips the panel above the anchor and clamps
               * `top` into [MARGIN, innerHeight - panelH - MARGIN], which places
               * a menu that FITS correctly — but a menu taller than the viewport
               * has no such position: the clamp bottoms out at `MARGIN` and the
               * overflow below simply gets cut, with `overflow-hidden` on the
               * className and no scroll to reach it. That is the "kebab options
               * are cut off" case that survives the portal and the flip: a full
               * row menu (five items plus a separator) against a short window, a
               * laptop at 125% zoom, or a phone in landscape.
               *
               * Bounding the height to the same two margins the hook reserves
               * makes the clamp always satisfiable, and `overflow-y-auto` below
               * turns the remainder into scroll instead of loss. 2 * MARGIN (8px
               * each) is duplicated as a literal rather than imported because
               * the hook does not export it; both numbers are only ever "the
               * viewport edge gap", and being a few px generous here is harmless
               * — the clamp, not this cap, decides the final position.
               */
              maxHeight: 'calc(100vh - 16px)',
            }}
            className={cn(
              // Scroll on the block axis only. `overflow-x` is pinned to hidden
              // explicitly because a `visible` axis computes to `auto` as soon as
              // its partner is not `visible` — setting only overflow-y would hand
              // the menu a horizontal scrollbar it has no use for. Clipping still
              // rounds the corners, as `overflow-hidden` did before.
              'fixed z-50 overflow-x-hidden overflow-y-auto rounded-lg border border-border/[0.1]',
              'bg-surface py-1 shadow-2xl',
            )}
          >
            {children(close)}
          </div>,
          document.body,
        )}
    </>
  );
}

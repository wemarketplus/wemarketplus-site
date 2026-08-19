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
            }}
            className={cn(
              'fixed z-50 overflow-hidden rounded-lg border border-border/[0.1]',
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

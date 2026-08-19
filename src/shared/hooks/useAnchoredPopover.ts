import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from 'react';

export interface AnchoredPosition {
  top: number;
  left: number;
}

interface Options {
  /** Whether the floating element is currently shown. */
  open: boolean;
  /** Close it — called on outside pointerdown, Escape, scroll and resize. */
  onClose: () => void;
  /** Width of the floating element in px, used for horizontal clamping. */
  width: number;
  /**
   * Horizontal alignment relative to the anchor. 'end' hangs the panel's right
   * edge off the anchor's right edge (row kebabs); 'start' aligns left edges
   * (form fields).
   */
  align?: 'start' | 'end';
}

// Gap between anchor and panel, and the minimum breathing room we insist on
// against the viewport edge before flipping or clamping.
const OFFSET = 4;
const MARGIN = 8;

/**
 * Positions a floating panel against an anchor element, in viewport coordinates.
 *
 * Exists because the app's popovers live inside containers that clip them.
 * DataTable wraps every table in `overflow-hidden` purely to clip corners to its
 * 14px radius, and that wrapper equally clips anything escaping the table box —
 * which is why the users table's kebab menu opened into invisible space on the
 * lower rows. z-index cannot defeat overflow clipping; only leaving the stacking
 * context does. So consumers render the panel through a portal to document.body
 * and place it with the `fixed` coordinates this hook returns.
 *
 * Because those coordinates are viewport-relative, the panel can also flip above
 * the anchor when there is no room below and clamp horizontally so it never runs
 * off a narrow screen.
 *
 * Returns the anchor ref to attach to the trigger, the panel ref used to measure
 * the real rendered height (which is what makes the flip decision correct for
 * both short and tall panels), and the computed position — `null` until measured,
 * so consumers can keep the panel hidden rather than flash it at 0,0.
 */
export function useAnchoredPopover<A extends HTMLElement, P extends HTMLElement>({
  open,
  onClose,
  width,
  align = 'end',
}: Options): {
  anchorRef: RefObject<A | null>;
  panelRef: RefObject<P | null>;
  position: AnchoredPosition | null;
} {
  const anchorRef = useRef<A | null>(null);
  const panelRef = useRef<P | null>(null);
  const [position, setPosition] = useState<AnchoredPosition | null>(null);

  // Measure after the panel is in the DOM but before paint, so the user never
  // sees it at a provisional spot.
  useLayoutEffect(() => {
    if (!open) {
      setPosition(null);
      return;
    }
    const anchor = anchorRef.current;
    if (!anchor) return;

    const a = anchor.getBoundingClientRect();
    const panelH = panelRef.current?.offsetHeight ?? 0;
    const spaceBelow = window.innerHeight - a.bottom;

    // Flip above only when it genuinely fits better there — flipping into an
    // even tighter space just moves the problem.
    const flipUp = spaceBelow < panelH + OFFSET + MARGIN && a.top > spaceBelow;
    const rawTop = flipUp ? a.top - panelH - OFFSET : a.bottom + OFFSET;
    const rawLeft = align === 'end' ? a.right - width : a.left;

    setPosition({
      top: Math.max(MARGIN, Math.min(rawTop, window.innerHeight - panelH - MARGIN)),
      left: Math.max(MARGIN, Math.min(rawLeft, window.innerWidth - width - MARGIN)),
    });
  }, [open, width, align]);

  useEffect(() => {
    if (!open) return;

    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (panelRef.current?.contains(target)) return;
      if (anchorRef.current?.contains(target)) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    // A fixed-position panel would otherwise detach from its anchor the moment
    // the page moves beneath it. Capture on scroll, since scroll does not bubble
    // and the scrolling ancestor is usually not the window.
    const onReflow = () => onClose();

    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', onReflow, true);
    window.addEventListener('resize', onReflow);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', onReflow, true);
      window.removeEventListener('resize', onReflow);
    };
  }, [open, onClose]);

  return { anchorRef, panelRef, position };
}

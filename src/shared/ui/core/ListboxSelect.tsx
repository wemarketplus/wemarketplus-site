import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown } from 'lucide-react';
import { useAnchoredPopover } from '@/shared/hooks/useAnchoredPopover';
import { cn } from '@/shared/utils/cn';
import { CONTROL_BASE, CONTROL_HEIGHT } from './controlStyles';

export interface ListboxOption {
  value: string;
  label: string;
  /** Secondary text shown after the label (the state name behind its code). */
  hint?: string;
}

interface ListboxSelectProps {
  /** Points the <Label htmlFor> at the trigger, so clicking the label opens it. */
  id?: string;
  value: string;
  onChange: (value: string) => void;
  /** Called when focus leaves the control — wire RHF's `onBlur` here. */
  onBlur?: () => void;
  options: readonly ListboxOption[];
  /** Shown when `value` matches no option. */
  placeholder?: string;
  disabled?: boolean;
  invalid?: boolean;
  className?: string;
  /**
   * Sizing for the chevron, for a trigger that is not field-sized. The 16px
   * default is right inside a 44px control and far too big inside a 22px status
   * pill — see StatusSelect, which wears this component's behaviour at badge
   * geometry.
   */
  chevronClassName?: string;
  /**
   * A floor for the panel width, in px. The panel is measured from the TRIGGER
   * so it lines up with the field it belongs to, which is exactly right for a
   * full-width form control and wrong for a shrink-wrapped pill: an 80px badge
   * would open an 80px list and clip its own option labels.
   */
  minPanelWidth?: number;
  /**
   * Geometry for the option ROWS, for a trigger that is not field-sized — the
   * sibling of `chevronClassName`, and needed for the same reason.
   *
   * The default row is sized for a form field: 14px text at 8px/14px padding,
   * so 37px each. Worn under a 22px status badge that is oversized twice over —
   * the type is larger than the badge's own 11px, and seven statuses then open a
   * panel more than ten times the height of the control that produced it.
   */
  optionClassName?: string;
  /**
   * Ceiling for the open panel, in px. Defaults to MAX_PANEL_HEIGHT, which is
   * sized for the 51-state list this component was built for; a compact list
   * whose rows are shorter wants a ceiling that matches, or it caps a list that
   * would have fitted and adds a scrollbar for the last few pixels.
   */
  maxPanelHeight?: number;
  /** Only needed when there is no visible <Label> to point at the trigger. */
  'aria-label'?: string;
}

// The tallest the option list may get. Eight-ish rows: enough that the list
// reads as a list and short enough that it cannot become a second page.
const MAX_PANEL_HEIGHT = 264;
// How long a run of keystrokes counts as one type-ahead word ("m","d" -> "MD").
const TYPEAHEAD_RESET_MS = 700;

/**
 * A single-select dropdown whose OPEN LIST HAS A BOUNDED HEIGHT.
 *
 * ── The bug this fixes ────────────────────────────────────────────────────────
 * The State field on Agency info (onboarding) and Settings > Organization was a
 * native <select> holding all 51 US states. A native select's popup is drawn by
 * the browser, not the page: it sizes itself to its option count, so 51 options
 * produce a list hundreds of pixels tall that Chrome then places wherever it
 * fits — routinely upward, straight over the settings tab strip above the form.
 * Nothing in CSS reaches that popup: `size`, `max-height` and `overflow` apply
 * to the closed control, never to the list. The only way to bound the list is to
 * stop letting the browser draw it, which is what this component is for.
 *
 * The panel is rendered through a portal in viewport coordinates (see
 * useAnchoredPopover for why a plain `absolute` child gets clipped here) and
 * capped at MAX_PANEL_HEIGHT with its own scrollbar, so a 51-entry list and a
 * 4-entry one both open to something that fits inside the layout.
 *
 * ── Keeping what the native control gave away ─────────────────────────────────
 * Replacing a <select> means re-earning its behaviour by hand, so this
 * implements the listbox pattern rather than a div that looks like one:
 * roving Arrow/Home/End over the options with `aria-activedescendant`, Enter and
 * Space to commit, Escape to cancel, and the type-ahead that lets someone reach
 * Maryland by typing "md". The trigger is a real <button> with `aria-expanded`
 * and `role="combobox"`, so it is focusable and announced. Geometry comes from
 * the shared CONTROL_BASE/CONTROL_HEIGHT, so it lines up with the <Input> beside
 * it exactly as the native select did.
 *
 * It is deliberately NOT a drop-in for every select in the app: a handful of
 * options is served better by the platform picker (which is also the right
 * control on touch). Reach for this when the list is long enough that the
 * browser's own popup stops being a popup.
 *
 * ── The SECOND reason to reach for it: an accidental commit that costs ────────
 * Length is not the only thing wrong with the platform popup. Which pixels of it
 * commit a value is also the platform's business, and its blank regions — the
 * list's own padding, its scroll gutter, the strip below the last row — commit
 * whatever is currently HIGHLIGHTED on mouse-up on some platforms. Nothing in
 * the page can intercept that, because the popup is not in the page.
 *
 * On a form field that is merely annoying: the value is wrong until submit, and
 * the user can see it and fix it. On a control wired to a live PATCH it is a
 * silent write to the record — "clicking an empty area of the Fee Status
 * dropdown selects a fee status", which is what moved StatusSelect onto this
 * component. So the rule is two-part: reach for this when the list is too long
 * for the platform popup, OR when a stray commit from it would hit the server.
 * Commit here happens only from an option's own `onPointerDown`; the panel's
 * padding belongs to a <ul> with no handler, so blank space is inert by
 * construction.
 */
export function ListboxSelect({
  id,
  value,
  onChange,
  onBlur,
  options,
  placeholder = 'Select…',
  disabled,
  invalid,
  className,
  chevronClassName,
  optionClassName,
  minPanelWidth,
  maxPanelHeight,
  'aria-label': ariaLabel,
}: ListboxSelectProps) {
  const panelCeiling = maxPanelHeight ?? MAX_PANEL_HEIGHT;
  const [open, setOpen] = useState(false);
  // Which option the keyboard is on. Not the selection — that only changes on
  // commit, so arrowing through the list never writes a value the user did not
  // choose (the native select's own behaviour on desktop).
  const [activeIndex, setActiveIndex] = useState(-1);
  // Measured from the trigger at open time so the panel is exactly as wide as
  // the field it belongs to, whatever the surrounding grid does with it.
  const [panelWidth, setPanelWidth] = useState(0);
  const typeahead = useRef({ term: '', at: 0 });
  const listRef = useRef<HTMLUListElement | null>(null);

  const close = useCallback(() => setOpen(false), []);
  // The width the panel will actually be drawn at — trigger width, floored.
  // Computed once so the popover's flip/clamp maths and the panel's own style
  // cannot disagree about how wide it is.
  const drawnWidth = Math.max(panelWidth, minPanelWidth ?? 0);
  const { anchorRef, panelRef, position } = useAnchoredPopover<
    HTMLButtonElement,
    HTMLDivElement
  >({ open, onClose: close, width: drawnWidth, align: 'start' });

  const selectedIndex = options.findIndex((o) => o.value === value);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : undefined;

  const openList = () => {
    if (disabled) return;
    setPanelWidth(anchorRef.current?.offsetWidth ?? 0);
    // Open onto the current selection, so the list starts where the value is
    // rather than at Alabama every time.
    setActiveIndex(selectedIndex >= 0 ? selectedIndex : 0);
    setOpen(true);
  };

  const commit = (index: number) => {
    const option = options[index];
    if (!option) return;
    onChange(option.value);
    close();
    anchorRef.current?.focus();
  };

  // Keep the active option in view while arrowing — without this the highlight
  // walks off the bottom of a capped list and the list looks frozen.
  useLayoutEffect(() => {
    if (!open || activeIndex < 0) return;
    const node = listRef.current?.children[activeIndex];
    node?.scrollIntoView({ block: 'nearest' });
  }, [open, activeIndex, position]);

  // Focus follows the panel so Tab and Escape land somewhere sensible, and the
  // list can own the keyboard while it is up.
  useEffect(() => {
    if (open) listRef.current?.focus();
  }, [open, position]);

  // …and comes back when the panel goes away without a selection (Escape, or a
  // page scroll dismissing it). The list was holding focus, so unmounting it
  // drops focus to <body> and the next Tab restarts from the top of the page.
  // Guarded on `body` so a dismissal that moved focus somewhere deliberate — an
  // outside click landing in the next field — is not yanked back here.
  const wasOpen = useRef(false);
  useEffect(() => {
    if (wasOpen.current && !open && document.activeElement === document.body) {
      anchorRef.current?.focus();
    }
    wasOpen.current = open;
  }, [open, anchorRef]);

  const moveTo = (next: number) => {
    if (options.length === 0) return;
    setActiveIndex(((next % options.length) + options.length) % options.length);
  };

  const onTypeahead = (key: string) => {
    const now = performance.now();
    const term =
      now - typeahead.current.at > TYPEAHEAD_RESET_MS
        ? key.toLowerCase()
        : typeahead.current.term + key.toLowerCase();
    typeahead.current = { term, at: now };
    const hit = options.findIndex(
      (o) =>
        o.label.toLowerCase().startsWith(term) ||
        (o.hint?.toLowerCase().startsWith(term) ?? false),
    );
    if (hit >= 0) setActiveIndex(hit);
    return hit >= 0;
  };

  const onListKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        moveTo(activeIndex + 1);
        break;
      case 'ArrowUp':
        moveTo(activeIndex - 1);
        break;
      case 'Home':
        moveTo(0);
        break;
      case 'End':
        moveTo(options.length - 1);
        break;
      case 'Enter':
      case ' ':
        commit(activeIndex);
        break;
      case 'Tab':
        // Let focus leave, but do not leave an orphaned panel behind it.
        close();
        return;
      default:
        // Single printable characters drive type-ahead; everything else
        // (Escape, shortcuts) is left to the hook and the browser.
        if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
          if (!onTypeahead(e.key)) return;
          break;
        }
        return;
    }
    e.preventDefault();
  };

  const onTriggerKeyDown = (e: React.KeyboardEvent) => {
    if (open) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openList();
    }
  };

  const listId = id ? `${id}-listbox` : undefined;

  return (
    <>
      <button
        id={id}
        ref={anchorRef}
        type="button"
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? listId : undefined}
        aria-label={ariaLabel}
        aria-invalid={invalid || undefined}
        disabled={disabled}
        onClick={() => (open ? close() : openList())}
        onKeyDown={onTriggerKeyDown}
        onBlur={onBlur}
        className={cn(
          CONTROL_BASE,
          CONTROL_HEIGHT,
          'flex items-center justify-between gap-2 text-left',
          open && 'border-primary',
          invalid && 'border-destructive/60',
          className,
        )}
      >
        <span className={cn('truncate', !selected && 'text-muted-soft')}>
          {selected ? selected.label : placeholder}
        </span>
        <ChevronDown
          aria-hidden="true"
          className={cn(
            'h-4 w-4 shrink-0 text-muted transition-transform',
            open && 'rotate-180',
            chevronClassName,
          )}
        />
      </button>

      {open &&
        createPortal(
          <div
            ref={panelRef}
            style={{
              top: position?.top ?? 0,
              left: position?.left ?? 0,
              width: drawnWidth || undefined,
              maxHeight: panelCeiling,
              // Hidden until measured, so the first paint is never at 0,0.
              visibility: position ? 'visible' : 'hidden',
            }}
            className="fixed z-50 overflow-hidden rounded-md border border-border/[0.12] bg-surface shadow-2xl"
          >
            <ul
              ref={listRef}
              id={listId}
              role="listbox"
              tabIndex={-1}
              aria-activedescendant={
                activeIndex >= 0 && listId ? `${listId}-${activeIndex}` : undefined
              }
              onKeyDown={onListKeyDown}
              onBlur={onBlur}
              style={{ maxHeight: panelCeiling }}
              className="overflow-y-auto py-1 outline-none"
            >
              {options.map((option, index) => {
                const isSelected = option.value === value;
                return (
                  <li
                    key={option.value}
                    id={listId ? `${listId}-${index}` : undefined}
                    role="option"
                    aria-selected={isSelected}
                    // pointerdown, not click: the popover's outside-pointerdown
                    // listener fires first otherwise and the panel is gone before
                    // the click lands.
                    onPointerDown={(e) => {
                      e.preventDefault();
                      commit(index);
                    }}
                    onPointerEnter={() => setActiveIndex(index)}
                    className={cn(
                      'flex cursor-pointer items-baseline gap-2 px-3.5 py-2 text-[14px] text-foreground',
                      index === activeIndex && 'bg-primary/[0.08]',
                      isSelected && 'font-semibold',
                      // Last, so a caller that passes its own padding or type
                      // size REPLACES the field-sized defaults above rather than
                      // fighting them (cn runs tailwind-merge).
                      optionClassName,
                    )}
                  >
                    <span>{option.label}</span>
                    {option.hint && (
                      <span className="truncate text-[12px] text-muted-soft">{option.hint}</span>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>,
          document.body,
        )}
    </>
  );
}

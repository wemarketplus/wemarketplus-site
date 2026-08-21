import {
  addMonths,
  format,
  isValid,
  parse,
  startOfMonth,
  startOfToday,
} from 'date-fns';
import { CalendarDays, ChevronLeft, ChevronRight } from 'lucide-react';
import {
  forwardRef,
  useCallback,
  useMemo,
  useRef,
  useState,
  type InputHTMLAttributes,
} from 'react';
import { createPortal } from 'react-dom';
import { useAnchoredPopover } from '@/shared/hooks/useAnchoredPopover';
import { cn } from '@/shared/utils/cn';
import { CONTROL_BASE, CONTROL_HEIGHT } from './controlStyles';

/**
 * The wire format. Identical to what `<input type="date">` puts in `.value`, so
 * every consumer — react-hook-form registrations, zod schemas, the DTOs on the
 * other side — keeps working unchanged. This is the whole reason the picker
 * stores text rather than a Date.
 */
export const DATE_VALUE_FORMAT = 'yyyy-MM-dd';

const PANEL_WIDTH = 268;
const WEEKDAYS = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];

export type DatePickerProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  'type' | 'value' | 'defaultValue' | 'min' | 'max'
> & {
  /** `yyyy-MM-dd`, or '' for empty. */
  value?: string;
  /**
   * Earliest/latest selectable date, `yyyy-MM-dd`. Days outside are disabled.
   *
   * Typed `string | number` rather than plain `string` to stay spread-compatible
   * with react-hook-form: `register()` returns `min`/`max` as `string | number`
   * (the native attributes accept numbers for numeric/range inputs), so a
   * narrower type here would make every `{...register('date')}` a type error at
   * the call site. Coerced to a string before parsing.
   */
  min?: string | number;
  max?: string | number;
};

/** Parses `yyyy-MM-dd` to a Date, or null. Never throws on partial input. */
function parseValue(v: string | number | undefined): Date | null {
  if (v === undefined || v === null || v === '') return null;
  const d = parse(String(v), DATE_VALUE_FORMAT, new Date());
  return isValid(d) ? d : null;
}

/**
 * The days to render for a month grid: leading blanks, then each day, so the 1st
 * lands under its real weekday. Blanks are null rather than adjacent-month dates
 * to keep the grid unambiguous about what is clickable.
 */
function monthGrid(month: Date): Array<Date | null> {
  const first = startOfMonth(month);
  const daysInMonth = new Date(
    first.getFullYear(),
    first.getMonth() + 1,
    0,
  ).getDate();
  const cells: Array<Date | null> = Array.from({ length: first.getDay() }, () => null);
  for (let d = 1; d <= daysInMonth; d += 1) {
    cells.push(new Date(first.getFullYear(), first.getMonth(), d));
  }
  return cells;
}

/**
 * The app's one date field: a text input plus a calendar popover.
 *
 * ── Why this exists ───────────────────────────────────────────────────────────
 * Every date field in the app was a bare `<input type="date">`. That does give a
 * picker — but only the browser's, whose calendar icon Chrome renders as a small
 * grey glyph, Safari omits entirely, and Firefox draws differently again, so the
 * fields neither looked like the rest of the design system nor read as pickers at
 * all on some machines. This replaces the platform control with one that looks
 * the same everywhere and matches the surrounding fields.
 *
 * ── What is deliberately preserved ────────────────────────────────────────────
 * The value stays a `yyyy-MM-dd` STRING (DATE_VALUE_FORMAT) — byte-identical to
 * what the native input produced. Nothing downstream had to change: the same
 * react-hook-form `register()` result is spread in, the same zod schemas
 * validate, the same DTO shape reaches the API. Swapping in a Date object would
 * have rippled through every form and every payload.
 *
 * Typing is still allowed — a keyboard user filling a form quickly should not be
 * forced through a calendar — but the text is only committed when it parses AND
 * falls inside min/max; otherwise the field reverts on blur to the last good
 * value. That is the "prevent invalid date input" requirement, without the
 * hostile behaviour of clearing what someone is halfway through typing.
 *
 * The popover is portalled and viewport-positioned for the same reason the row
 * menus are (see useAnchoredPopover): a calendar opening from a field near the
 * bottom of a scrolling modal would otherwise be clipped by the modal's own box.
 */
export const DatePicker = forwardRef<HTMLInputElement, DatePickerProps>(
  ({ className, value, min, max, onChange, onBlur, disabled, name, id, ...props }, ref) => {
    const [open, setOpen] = useState(false);
    // What the user is typing. Null means "not editing" — show `value`.
    const [draft, setDraft] = useState<string | null>(null);

    // The real input node. `emit` writes through it, so it must be reachable
    // here even when the caller (react-hook-form's `register()`) also wants the
    // ref — hence the fan-out callback below rather than passing `ref` straight
    // through.
    const inputRef = useRef<HTMLInputElement | null>(null);
    const setInputRef = useCallback(
      (node: HTMLInputElement | null) => {
        inputRef.current = node;
        if (typeof ref === 'function') ref(node);
        else if (ref) ref.current = node;
      },
      [ref],
    );

    const close = useCallback(() => setOpen(false), []);
    const { anchorRef, panelRef, position } = useAnchoredPopover<
      HTMLDivElement,
      HTMLDivElement
    >({ open, onClose: close, width: PANEL_WIDTH, align: 'start' });

    const selected = useMemo(() => parseValue(value), [value]);
    const minDate = useMemo(() => parseValue(min), [min]);
    const maxDate = useMemo(() => parseValue(max), [max]);

    // The month on display. Follows the selection when there is one, else today.
    const [viewMonth, setViewMonth] = useState<Date>(
      () => startOfMonth(selected ?? startOfToday()),
    );

    const isOutOfRange = useCallback(
      (d: Date) => {
        if (minDate && d < minDate) return true;
        if (maxDate && d > maxDate) return true;
        return false;
      },
      [minDate, maxDate],
    );

    /**
     * Writes `next` into the real input and lets React's own change plumbing
     * carry it to whatever is listening.
     *
     * A synthetic `{target: {name, value}}` object handed straight to `onChange`
     * does NOT work here, which is worth recording because it looks like it
     * should: react-hook-form's change handler checks `target.type` first, and
     * for any element that has one it re-reads the value from the ref it
     * registered — the actual DOM node — ignoring the value on the object it was
     * passed. The field silently stayed empty after every calendar pick.
     *
     * So write the value onto the real node first — through the prototype setter,
     * since React installs its own `value` property and tracks the last value it
     * wrote — and only then hand that same node to the caller's `onChange`. RHF
     * re-reads the ref it registered, which is this node, and sees the new value.
     *
     * Dispatching a native `input` event instead would not do: the element's
     * React `onChange` is this component's own draft handler, not the caller's,
     * so the event would never reach the form.
     */
    const emit = useCallback(
      (next: string) => {
        const el = inputRef.current;
        if (!el) return;
        Object.getOwnPropertyDescriptor(
          window.HTMLInputElement.prototype,
          'value',
        )?.set?.call(el, next);
        onChange?.({
          target: el,
          currentTarget: el,
        } as unknown as React.ChangeEvent<HTMLInputElement>);
      },
      [onChange],
    );

    const pick = (d: Date) => {
      if (isOutOfRange(d)) return;
      emit(format(d, DATE_VALUE_FORMAT));
      setDraft(null);
      setOpen(false);
    };

    /**
     * Normalise whatever text is in the field on blur.
     *
     * The current text lives in the DOM node in uncontrolled mode and in `draft`
     * in controlled mode, so read the node either way — it is correct in both.
     * A value that parses and is in range is rewritten in canonical form; one
     * that does not is discarded, which is the "prevent invalid date input" rule
     * applied at the only moment it is not hostile to do so (the user has left
     * the field, so they are not mid-keystroke).
     */
    const commitDraft = () => {
      const text = inputRef.current?.value ?? '';
      if (text === '') {
        if (draft !== null) emit('');
      } else {
        const parsed = parseValue(text);
        if (parsed && !isOutOfRange(parsed)) {
          emit(format(parsed, DATE_VALUE_FORMAT));
          setViewMonth(startOfMonth(parsed));
        } else {
          emit('');
        }
      }
      setDraft(null);
    };

    return (
      <div ref={anchorRef} className="relative">
        <input
          ref={setInputRef}
          id={id}
          name={name}
          type="text"
          inputMode="numeric"
          autoComplete="off"
          placeholder={DATE_VALUE_FORMAT}
          disabled={disabled}
          // Controlled ONLY when the caller actually supplies a value. This
          // matters more than it looks: react-hook-form's `register()` returns
          // `{name, onChange, onBlur, ref}` and NO value — it drives the field
          // through the ref. Binding `value={... ?? ''}` unconditionally made
          // every registered field a controlled input pinned to the empty string,
          // and React reset the box on every render, so a picked date vanished
          // immediately. Uncontrolled here means the DOM node holds the text and
          // RHF stays in charge of it, exactly as with the native input.
          {...(value === undefined ? {} : { value: draft ?? value })}
          onChange={(e) => {
            // Controlled: hold the keystrokes locally until they parse.
            // Uncontrolled: the node already shows them, so just pass them on.
            if (value === undefined) onChange?.(e);
            else setDraft(e.target.value);
          }}
          onBlur={(e) => {
            commitDraft();
            onBlur?.(e);
          }}
          className={cn(CONTROL_BASE, CONTROL_HEIGHT, 'pr-11 placeholder:text-faint', className)}
          {...props}
        />
        <button
          type="button"
          tabIndex={-1}
          disabled={disabled}
          aria-label="Open calendar"
          onClick={() => {
            setViewMonth(startOfMonth(parseValue(draft ?? value ?? '') ?? startOfToday()));
            setOpen((v) => !v);
          }}
          className={cn(
            'absolute right-1 top-1/2 flex h-9 w-9 -translate-y-1/2 items-center justify-center',
            'rounded-md text-muted transition-colors hover:bg-foreground/[0.06] hover:text-foreground',
            'disabled:cursor-not-allowed disabled:opacity-50',
          )}
        >
          <CalendarDays className="h-[18px] w-[18px]" />
        </button>

        {open &&
          createPortal(
            <div
              ref={panelRef}
              style={{
                top: position?.top ?? 0,
                left: position?.left ?? 0,
                width: PANEL_WIDTH,
                visibility: position ? 'visible' : 'hidden',
              }}
              className="fixed z-50 rounded-[12px] border border-border/[0.1] bg-surface p-3 shadow-2xl"
            >
              <div className="mb-2 flex items-center justify-between">
                <button
                  type="button"
                  aria-label="Previous month"
                  onClick={() => setViewMonth((m) => addMonths(m, -1))}
                  className="flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-foreground/[0.06] hover:text-foreground"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <span className="text-[13px] font-semibold text-foreground">
                  {format(viewMonth, 'MMMM yyyy')}
                </span>
                <button
                  type="button"
                  aria-label="Next month"
                  onClick={() => setViewMonth((m) => addMonths(m, 1))}
                  className="flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-foreground/[0.06] hover:text-foreground"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>

              <div className="grid grid-cols-7 gap-0.5">
                {WEEKDAYS.map((d) => (
                  <span
                    key={d}
                    className="flex h-7 items-center justify-center text-[10px] font-semibold uppercase text-muted-soft"
                  >
                    {d}
                  </span>
                ))}
                {monthGrid(viewMonth).map((day, i) =>
                  day === null ? (
                    // Leading blanks have no identity of their own; the index is
                    // stable because the grid is rebuilt per month.
                    <span key={`blank-${i}`} />
                  ) : (
                    <button
                      key={day.toISOString()}
                      type="button"
                      disabled={isOutOfRange(day)}
                      aria-current={
                        selected && format(day, DATE_VALUE_FORMAT) ===
                        format(selected, DATE_VALUE_FORMAT)
                          ? 'date'
                          : undefined
                      }
                      onClick={() => pick(day)}
                      className={cn(
                        'flex h-8 items-center justify-center rounded-md text-[12px] transition-colors',
                        'hover:bg-primary/[0.12] disabled:cursor-not-allowed disabled:opacity-30 disabled:hover:bg-transparent',
                        selected &&
                          format(day, DATE_VALUE_FORMAT) === format(selected, DATE_VALUE_FORMAT)
                          ? 'bg-primary font-semibold text-white hover:bg-primary'
                          : 'text-foreground',
                        !selected &&
                          format(day, DATE_VALUE_FORMAT) ===
                            format(startOfToday(), DATE_VALUE_FORMAT) &&
                          'font-semibold text-primary',
                      )}
                    >
                      {day.getDate()}
                    </button>
                  ),
                )}
              </div>

              <div className="mt-2 flex items-center justify-between border-t border-border/[0.07] pt-2">
                <button
                  type="button"
                  onClick={() => pick(startOfToday())}
                  className="rounded-md px-2 py-1 text-[12px] text-primary hover:bg-primary/[0.08]"
                >
                  Today
                </button>
                <button
                  type="button"
                  onClick={() => {
                    emit('');
                    setDraft(null);
                    setOpen(false);
                  }}
                  className="rounded-md px-2 py-1 text-[12px] text-muted hover:bg-foreground/[0.06]"
                >
                  Clear
                </button>
              </div>
            </div>,
            document.body,
          )}
      </div>
    );
  },
);
DatePicker.displayName = 'DatePicker';

import { forwardRef, useState, type KeyboardEvent } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { toast } from 'sonner';
import { Input, type InputProps } from './Input';
import { cn } from '@/shared/utils/cn';

/**
 * Copies the field's selection (or its whole value, if nothing is selected) to
 * the clipboard, and reports whether it got there.
 *
 * ── The bug this exists for ───────────────────────────────────────────────────
 * QA: "enter a password, copy it, paste it into Confirm password — the paste does
 * not work." The paste was never the problem; nothing in this app blocks it, and
 * a real Ctrl+V does insert clipboard content and does reach react-hook-form. The
 * COPY was failing, silently: a browser will not put the value of an
 * `input[type=password]` on the clipboard. Ctrl+C in a masked field is a no-op,
 * so the paste that followed pasted whatever was on the clipboard already —
 * which reads exactly like a broken paste.
 *
 * ── Why it has to be done from `keydown` ──────────────────────────────────────
 * The obvious hook, a `copy` listener, does not exist here. Measured in-page with
 * all 20 characters selected: a masked input fires NO `copy` event at all, and
 * fires one normally the instant the eye toggle flips it to `text`. The browser
 * refuses at the source and never tells the page. `keydown` DOES fire either way,
 * and `selectionStart`/`selectionEnd` are readable on a password input, so the
 * page can see the shortcut, take the characters itself and write them with the
 * async Clipboard API — which has no equivalent restriction.
 *
 * ── The trade-off, stated ─────────────────────────────────────────────────────
 * This deliberately defeats a browser protection: the value of a masked field now
 * reaches the OS clipboard. That is what was asked for, it is what every password
 * manager already does, and the alternative was a step that fails without saying
 * so. It stays scoped to the shortcut the user actually pressed — no copy button,
 * nothing automatic, and the field must be focused with its text selected.
 */
async function copyFieldToClipboard(el: HTMLInputElement): Promise<boolean> {
  const start = el.selectionStart ?? 0;
  const end = el.selectionEnd ?? 0;
  // No selection → the whole value. Native Ctrl+C would copy nothing, but
  // "click the field, Ctrl+C" is what people actually do, and a password field
  // holds exactly one thing, so there is no ambiguity about what was meant.
  const text = start === end ? el.value : el.value.slice(start, end);
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // writeText needs a secure context and clipboard-write permission. Both hold
    // on https and on localhost, but not on a plain-http deployment — and a
    // rejection here is precisely the silent failure this fix exists to remove,
    // so it has to say something rather than swallow it.
    return false;
  }
}

export const PasswordInput = forwardRef<HTMLInputElement, InputProps>(
  ({ className, onKeyDown, ...props }, ref) => {
    const [visible, setVisible] = useState(false);

    const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
      /**
       * Only while MASKED. Once the eye toggle has revealed the field it is an
       * ordinary text input: the native copy works, and so do cut, drag and the
       * context menu, none of which this would reproduce. Intercepting there
       * would replace working behaviour with a narrower imitation of it.
       */
      const isCopyShortcut =
        !visible &&
        (event.ctrlKey || event.metaKey) &&
        !event.altKey &&
        !event.shiftKey &&
        (event.key === 'c' || event.key === 'C');

      if (isCopyShortcut) {
        // Before the await: `currentTarget` is null by the time a promise
        // continuation runs, since React pools nothing but the browser still
        // reuses the event.
        const el = event.currentTarget;
        event.preventDefault();
        void copyFieldToClipboard(el).then((ok) => {
          if (!ok) {
            toast.error(
              'Could not copy the password. Reveal it with the eye icon and copy it manually.',
            );
          }
        });
      }

      onKeyDown?.(event);
    };

    return (
      <div className="relative">
        <Input
          ref={ref}
          {...props}
          onKeyDown={handleKeyDown}
          type={visible ? 'text' : 'password'}
          className={cn('pr-11', className)}
        />
        <button
          type="button"
          aria-label={visible ? 'Hide password' : 'Show password'}
          title={visible ? 'Hide password' : 'Show password'}
          aria-pressed={visible}
          onClick={() => setVisible((v) => !v)}
          className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-muted-soft transition-colors hover:text-foreground"
        >
          {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    );
  },
);
PasswordInput.displayName = 'PasswordInput';

import { Search } from 'lucide-react';
import {
  HEADER_CONTROL_BASE,
  HEADER_CONTROL_HEIGHT,
} from '@/shared/ui/core/controlStyles';
import { cn } from '@/shared/utils/cn';
import { CommandPalette } from './CommandPalette';
import { useCommandPalette } from './useCommandPalette';

// Self-contained global-search entry point for the shell: a header trigger
// button, the Cmd/Ctrl+K shortcut, and the palette modal. DashboardHeader drops
// this in as a single element — no palette state to manage there.
export function GlobalSearch() {
  const { open, openPalette, closePalette } = useCommandPalette();
  const isMac =
    typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

  return (
    <>
      <button
        type="button"
        onClick={openPalette}
        aria-label="Search"
        // Geometry, hairline and surface all come from HEADER_CONTROL_* rather
        // than being restated here — this button, the product switcher and the
        // profile chip each used to carry their own copy of the same border and
        // background, which is how a "search field" ends up looking like it
        // belongs to a different design language from the controls beside it.
        //
        // `pl-3` is the SAME 12px inset the in-page search fields give their
        // icon (CONTROL_ICON_INSET), so the two search affordances on a list
        // page — this trigger and the field below it — put their magnifier at
        // the same distance from the left edge. `pr-2` is tighter on purpose:
        // the ⌘K chip carries its own visual padding.
        //
        // The icon is 16px (h-4), the same as the bell and the sign-out glyph
        // beside it — it was 14px, which read as a lighter, smaller control
        // than its neighbours at the same nominal size.
        className={cn(
          HEADER_CONTROL_BASE,
          HEADER_CONTROL_HEIGHT,
          'flex items-center gap-2 pl-3 pr-2 text-[12px] text-muted hover:text-foreground',
        )}
      >
        <Search className="h-4 w-4 shrink-0" />
        <span className="hidden sm:inline">Search…</span>
        <kbd className="hidden items-center rounded bg-foreground/[0.06] px-1.5 py-0.5 text-[10px] leading-none text-muted-soft sm:inline-flex">
          {isMac ? '⌘' : 'Ctrl'} K
        </kbd>
      </button>
      <CommandPalette open={open} onClose={closePalette} />
    </>
  );
}

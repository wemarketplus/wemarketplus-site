import { Search } from 'lucide-react';
import { cn } from '@/shared/utils/cn';
import { FI } from '../styles';

interface DemoSearchProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}

/**
 * The demo skin's search field — an FI input with a leading magnifier.
 *
 * The three demo dashboards each hand-rolled this as a bare `<input autoComplete="off" className={FI}>`,
 * so a search box was indistinguishable from a plain text field: no glyph to mark it
 * as one, and nothing to echo the magnifier every filter bar in the signed-in app
 * carries. That is the "icon positioning" half of the styling report — there was no
 * icon to position.
 *
 * Mirrors <SearchInput>'s construction rather than its measurements: the same
 * relative wrapper and the same `inset-y-0` + flex centring (a `top-1/2` translate
 * rounds to a half-pixel at some zoom levels), scaled to this skin's tighter 34px
 * control. Inset and the padding that reserves room for it are ONE pair — 11px to
 * match FI's own `px-[11px]`, a 14px glyph, and 32px of text inset after it.
 */
export function DemoSearch({ value, onChange, placeholder = 'Search…', className }: DemoSearchProps) {
  return (
    <div className={cn('relative', className)}>
      <span className="pointer-events-none absolute inset-y-0 left-[11px] flex items-center">
        <Search className="h-3.5 w-3.5 text-[#4b6278]" />
      </span>
      <input
        autoComplete="off"
        className={cn(FI, 'pl-[32px]')}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

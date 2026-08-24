import { forwardRef } from 'react';
import { Search, X } from 'lucide-react';
import { Input, type InputProps } from './Input';
import { CONTROL_ICON_INSET, CONTROL_ICON_PADDING } from './controlStyles';
import { cn } from '@/shared/utils/cn';

export interface SearchInputProps extends Omit<InputProps, 'value' | 'onChange' | 'type'> {
  value: string;
  onChange: (value: string) => void;
  /**
   * Sizing/layout for the wrapper, which is what a filter bar actually needs to
   * control — `max-w-sm flex-1`, `sm:w-64`, and so on. `className` still lands
   * on the input itself. Without this the 19 filter bars that each hand-rolled
   * this markup had no way to adopt the shared component, which is why they
   * all kept their own copy of it.
   */
  wrapperClassName?: string;
}

// A text input with a leading search icon and a trailing clear (X) button,
// the latter shown only once there is something to clear. Mirrors
// PasswordInput's icon-in-input convention (relative wrapper + absolutely
// positioned button) so every searchable list filter looks and behaves the
// same way.
//
// The icon is centred with `inset-y-0` + flex rather than `top-1/2` +
// `-translate-y-1/2`: the translate approach rounds to a half-pixel at some
// zoom levels and heights, which is the faint "search icon sits a hair high"
// misalignment. Matching the clear button's own centring also guarantees the
// two glyphs agree with each other.
export const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(
  (
    { value, onChange, className, wrapperClassName, placeholder = 'Search…', ...props },
    ref,
  ) => (
    <div className={cn('relative', wrapperClassName)}>
      {/* Inset and the padding that reserves room for it are ONE pair from
          controlStyles, not two literals that have to be kept in step. */}
      <span
        className={cn(
          'pointer-events-none absolute inset-y-0 flex items-center',
          CONTROL_ICON_INSET,
        )}
      >
        <Search className="h-4 w-4 text-muted" />
      </span>
      <Input
        ref={ref}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={cn(CONTROL_ICON_PADDING, value && 'pr-9', className)}
        {...props}
      />
      {value && (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => onChange('')}
          className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-muted-soft transition-colors hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  ),
);
SearchInput.displayName = 'SearchInput';

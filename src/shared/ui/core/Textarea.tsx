import { forwardRef, type TextareaHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

export type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>;

// Matches the demo `.fi` textarea: dark surface, 10px radius, vertical resize.
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, rows = 4, ...props }, ref) => (
    <textarea
      ref={ref}
      rows={rows}
      // Autofill off, matching <Input> and <Select> — see the note on Input.
      // A textarea is not exempt: `street-address` is the one profile field
      // Chrome will write into one, and every textarea in this app holds notes
      // about a record, never the filler's own address.
      autoComplete="off"
      className={cn(
        'w-full resize-y rounded-md border border-border/[0.12] bg-surface-raised px-3.5 py-2.5 text-[14px] text-foreground outline-none transition-colors placeholder:text-faint focus:border-primary disabled:opacity-50',
        className,
      )}
      {...props}
    />
  ),
);
Textarea.displayName = 'Textarea';

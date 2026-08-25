import { forwardRef, type HTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';
import { SECTION_SUBTITLE, SECTION_TITLE } from './typography';

// Mirrors wemarketplus-site `.card`: 1px hairline border on the card surface at
// a 14px radius.
//
// ONE radius, for every card. `dense` used to select it — `dense ?
// 'rounded-[14px]' : 'rounded-[14px]'` — a ternary whose branches are the same
// string, so the prop had no effect at all while reading, at a glance, as though
// it did. Rather than reviving a second radius (which is the opposite of what a
// consistent surface needs), the prop is now explicitly accepted and ignored:
// ~40 call sites pass it, and they are all asking for "a card".
export const Card = forwardRef<
  HTMLDivElement,
  HTMLAttributes<HTMLDivElement> & {
    /** @deprecated No longer changes anything — every card is one radius. */
    dense?: boolean;
  }
>(({ className, dense: _dense, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      'rounded-card border border-border/[0.09] bg-surface text-foreground',
      className,
    )}
    {...props}
  />
));
Card.displayName = 'Card';

export const CardHeader = ({ className, ...props }: HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('flex flex-col gap-1.5 p-6 pb-4', className)} {...props} />
);

// Same constant as <SectionHeader>: a card's title and a section's title are the
// same thing at the same level, and they were 18px/800 against 22px/900.
export const CardTitle = ({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) => (
  <h3 className={cn(SECTION_TITLE, className)} {...props} />
);

export const CardDescription = ({
  className,
  ...props
}: HTMLAttributes<HTMLParagraphElement>) => (
  <p className={cn(SECTION_SUBTITLE, className)} {...props} />
);

export const CardContent = ({ className, ...props }: HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('px-6 pb-6', className)} {...props} />
);

export const CardFooter = ({ className, ...props }: HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn('flex items-center gap-3 border-t border-border/[0.07] px-6 py-4', className)}
    {...props}
  />
);

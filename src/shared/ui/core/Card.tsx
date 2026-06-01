import { forwardRef, type HTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site `.card`: #0d1b31 bg, 1px white/.09 border,
// 18px radius. Dashboard cards in crm-*.html use the same surface at a
// 14px radius — exposed via the `dense` flag.
export const Card = forwardRef<
  HTMLDivElement,
  HTMLAttributes<HTMLDivElement> & { dense?: boolean }
>(({ className, dense, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      'border border-white/[0.09] bg-surface text-foreground',
      dense ? 'rounded-[14px]' : 'rounded-[18px]',
      className,
    )}
    {...props}
  />
));
Card.displayName = 'Card';

export const CardHeader = ({ className, ...props }: HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('flex flex-col gap-1.5 p-6 pb-4', className)} {...props} />
);

export const CardTitle = ({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) => (
  <h3
    className={cn('text-[18px] font-extrabold leading-tight text-foreground', className)}
    {...props}
  />
);

export const CardDescription = ({
  className,
  ...props
}: HTMLAttributes<HTMLParagraphElement>) => (
  <p className={cn('text-[13px] leading-relaxed text-muted', className)} {...props} />
);

export const CardContent = ({ className, ...props }: HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('px-6 pb-6', className)} {...props} />
);

export const CardFooter = ({ className, ...props }: HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn('flex items-center gap-3 border-t border-white/[0.07] px-6 py-4', className)}
    {...props}
  />
);

import { cn } from '@/shared/utils/cn';
import type { BadgeTone } from '../types/clDemoTypes';

const TONE: Record<BadgeTone, string> = {
  green: 'bg-[#4fc87a]/10 text-[#4fc87a]',
  amber: 'bg-[#f59e0b]/10 text-[#f59e0b]',
  blue: 'bg-[#3d9ee8]/10 text-[#3d9ee8]',
  red: 'bg-[#f87171]/10 text-[#f87171]',
  neutral: 'bg-white/[0.07] text-[#8ba4c4]',
};

// Pill badge — reproduces the reference .badge + .bg/.ba/.bb/.br/.bx classes.
export function Badge({
  tone,
  children,
  className,
}: {
  tone: BadgeTone;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-block rounded-full px-2 py-0.5 text-[10px] font-bold',
        TONE[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

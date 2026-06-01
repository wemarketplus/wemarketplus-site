import { Layers } from 'lucide-react';
import { cn } from '@/shared/utils/cn';

interface BrandLogoProps {
  className?: string;
  // 'light' = white wordmark (nav on dark), used everywhere on the site.
  size?: 'sm' | 'md';
}

// Mirrors the live wemarketplus.com nav logo: a sage stacked-layers tile +
// "We Market Plus" wordmark + a small azure "CRM" superscript.
export function BrandLogo({ className, size = 'md' }: BrandLogoProps) {
  const tile = size === 'sm' ? 'h-7 w-7' : 'h-[30px] w-[30px]';
  const word = size === 'sm' ? 'text-[15px]' : 'text-[17px]';
  return (
    <span className={cn('inline-flex items-center gap-2.5 select-none', className)}>
      <span
        className={cn(
          'flex items-center justify-center rounded-[7px] bg-gradient-to-br from-sage to-[#2da856] text-[#06080e]',
          tile,
        )}
      >
        <Layers className="h-4 w-4" strokeWidth={2.5} />
      </span>
      <span className={cn('font-bold tracking-tight text-foreground', word)}>
        We Market Plus
        <sup className="ml-0.5 text-[9px] font-bold text-azure">CRM</sup>
      </span>
    </span>
  );
}

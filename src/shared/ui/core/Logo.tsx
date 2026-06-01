import { Product } from '@/shared/types';
import { cn } from '@/shared/utils/cn';

interface LogoProps {
  className?: string;
  showSubtitle?: boolean;
  size?: 'sm' | 'md' | 'lg';
  product?: Product;
}

// Mirrors wemarketplus-site `.logo-mark`: a text-only split-tone wordmark.
// HospiceLink → "Hospice"(azure) + "Link"(gold), subtitle "HIPAA-COMPLIANT
// HOSPICE CRM". CommunityLink → "Community"(azure) + "Link"(amber).
// 900 weight, -1px letter-spacing, 12px muted subtitle.
export function Logo({
  className,
  showSubtitle = true,
  size = 'md',
  product = Product.HospiceLink,
}: LogoProps) {
  const markSize = {
    sm: 'text-[20px]',
    md: 'text-[24px]',
    lg: 'text-[28px]',
  }[size];

  const isCommunity = product === Product.CommunityLink;
  const head = isCommunity ? 'Community' : 'Hospice';
  const tailColor = isCommunity ? 'text-amber' : 'text-gold';
  const subtitle = isCommunity
    ? 'SENIOR LIVING CRM'
    : 'HIPAA-COMPLIANT HOSPICE CRM';

  return (
    <div className={cn('select-none text-center', className)}>
      <div
        className={cn(
          'font-black leading-none tracking-[-1px] text-azure',
          markSize,
        )}
      >
        {head}
        <span className={tailColor}>Link</span>
      </div>
      {showSubtitle && (
        <div className="mt-1 text-[12px] tracking-[0.05em] text-muted">
          {subtitle}
        </div>
      )}
    </div>
  );
}

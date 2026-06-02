import { Product } from '@/shared/types';
import { Card, Logo, SecurityBadges } from '@/shared/ui/core';
import type { AuthCardShellProps } from '../types/authTypes';

// Mirrors the wemarketplus-site auth layout exactly: centered column
// (max-width 420/440px), logo block with 28px bottom margin, a #0d1b31 card
// (18px radius, 32px/28px padding) with .card-title (18px/800) + .card-sub
// (13px muted), then the HIPAA footer. No halo, no eyebrow — the source has
// neither.
export function AuthCardShell({
  title,
  description,
  children,
  product = Product.HospiceLink,
  hideFooter = false,
  maxWidth = 420,
}: AuthCardShellProps) {
  return (
    <div
      data-product={product}
      className="flex min-h-screen items-center justify-center bg-bg px-5 py-5"
    >
      <div
        className="w-full"
        style={{ maxWidth: `${maxWidth}px` }}
      >
        {/* .logo */}
        <div className="mb-7">
          <Logo size="lg" product={product} />
        </div>

        {/* .card */}
        <Card className="px-7 py-8">
          <div className="mb-1.5 text-[18px] font-extrabold text-foreground">
            {title}
          </div>
          {description && (
            <div className="mb-6 text-[13px] leading-relaxed text-muted">
              {description}
            </div>
          )}
          {children}
        </Card>

        {/* .footer-ctr */}
        {!hideFooter && (
          <div className="mt-4">
            <SecurityBadges />
          </div>
        )}
      </div>
    </div>
  );
}

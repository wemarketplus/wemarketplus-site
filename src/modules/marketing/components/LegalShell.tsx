import type { ReactNode } from 'react';
import { Card, CardContent } from '@/shared/ui/core';
import { MarketingShell } from './MarketingShell';

interface LegalShellProps {
  eyebrow: string;
  title: string;
  effective?: string;
  children: ReactNode;
}

// Layout used by privacy/terms/compliance/sign-baa screens.
export function LegalShell({
  eyebrow,
  title,
  effective,
  children,
}: LegalShellProps) {
  return (
    <MarketingShell>
      <section className="mx-auto max-w-3xl px-6 py-16">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-soft">
          {eyebrow}
        </p>
        <h1 className="mt-3 font-serif-display text-4xl leading-tight text-foreground">
          {title}
        </h1>
        {effective && (
          <p className="mt-2 text-xs text-muted-soft">Effective {effective}</p>
        )}
        <Card className="mt-8">
          <CardContent className="space-y-4 px-6 py-7 text-sm leading-relaxed text-muted">
            {children}
          </CardContent>
        </Card>
      </section>
    </MarketingShell>
  );
}

import { ShieldCheck } from 'lucide-react';
import { PortalNav } from './PortalNav';
import type { PortalShellProps } from '../types/complianceTypes';

// Wraps every Compliance Portal screen with the portal header + sub-nav.
export function PortalShell({ title, description, children }: PortalShellProps) {
  return (
    <div className="space-y-6">
      <header className="flex items-start gap-4">
        <div className="flex h-11 w-11 items-center justify-center rounded-md bg-azure/15 text-azure ring-1 ring-azure/20">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <h1 className="font-display text-3xl text-foreground">{title}</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted">{description}</p>
        </div>
      </header>
      <PortalNav />
      {children}
    </div>
  );
}

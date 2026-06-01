import { Check, ShieldCheck } from 'lucide-react';
import { ROLE_LABELS } from '@/shared/rbac';
import { Card, CardContent } from '@/shared/ui/core';
import { useRoleCapabilities } from '../hooks/useRoleCapabilities';

export function PermissionsPage() {
  const capabilities = useRoleCapabilities();

  return (
    <div className="space-y-8">
      <header className="flex items-start gap-4">
        <div className="flex h-11 w-11 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <h1 className="font-display text-3xl leading-tight text-foreground">
            Roles &amp; permissions
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted">
            The backend is role-based: every user has one of three roles, enforced in
            NestJS via <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-foreground">@Roles()</code> guards.
            This matrix mirrors the route-level checks so you can audit who can do what.
          </p>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {capabilities.map((cap) => (
          <Card key={cap.role} className="flex flex-col">
            <CardContent className="flex flex-1 flex-col gap-4 px-6 py-6">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold text-foreground">
                  {ROLE_LABELS[cap.role]}
                </h2>
                <span className="rounded-pill bg-primary/10 px-2.5 py-1 text-[10px] uppercase tracking-[0.1em] text-primary">
                  {cap.role}
                </span>
              </div>
              <p className="text-sm text-muted">{cap.description}</p>
              <ul className="mt-auto space-y-2.5 border-t border-white/[0.06] pt-4">
                {cap.capabilities.map((entry) => (
                  <li
                    key={entry}
                    className="flex items-start gap-2.5 text-[13px] text-foreground"
                  >
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                    <span>{entry}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

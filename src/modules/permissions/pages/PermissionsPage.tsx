import { ShieldCheck } from 'lucide-react';
import { useRoleCapabilities } from '../hooks/useRoleCapabilities';
import { RoleCapabilityCard } from '../components/RoleCapabilityCard';

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
          <RoleCapabilityCard key={cap.role} cap={cap} />
        ))}
      </div>
    </div>
  );
}

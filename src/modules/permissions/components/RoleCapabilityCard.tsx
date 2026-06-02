import { Check } from 'lucide-react';
import { ROLE_LABELS } from '@/shared/rbac';
import { Card, CardContent } from '@/shared/ui/core';
import type { RoleCapability } from '../types/permissionsTypes';

interface RoleCapabilityCardProps {
  cap: RoleCapability;
}

// Presentational card for a single role's capability list. Pure render — no
// business logic; the matrix is provided by the page via useRoleCapabilities.
export function RoleCapabilityCard({ cap }: RoleCapabilityCardProps) {
  return (
    <Card className="flex flex-col">
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
  );
}

import { Sliders, ToggleRight, UserCog } from 'lucide-react';
import { toast } from 'sonner';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';

const CONTROLS = [
  {
    id: 'impersonate',
    icon: UserCog,
    title: 'Impersonate user',
    description: 'Sign in as any customer to reproduce an issue from their side.',
    cta: 'Open impersonator',
  },
  {
    id: 'flags',
    icon: ToggleRight,
    title: 'Feature flags',
    description: 'Toggle experimental features per tenant or globally.',
    cta: 'Manage flags',
  },
  {
    id: 'system',
    icon: Sliders,
    title: 'System parameters',
    description: 'Rate limits, queue depths, and AI budget controls.',
    cta: 'Open parameters',
  },
];

export function OwnerAdminControlsPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Admin controls"
        description="High-leverage levers for running the platform."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {CONTROLS.map((c) => {
          const Icon = c.icon;
          return (
            <Card key={c.id}>
              <CardContent className="space-y-4 px-6 py-6">
                <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
                  <Icon className="h-4 w-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-foreground">{c.title}</h2>
                  <p className="mt-1 text-sm text-muted">{c.description}</p>
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => toast.message(`${c.title} — backend not wired`)}
                >
                  {c.cta}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

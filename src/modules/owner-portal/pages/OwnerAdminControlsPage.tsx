import { Button, Card, CardContent } from '@/shared/ui/core';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { useOwnerAdminControls } from '../hooks/useOwnerAdminControls';

export function OwnerAdminControlsPage() {
  const { controls, runControl } = useOwnerAdminControls();

  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Admin controls"
        description="High-leverage levers for running the platform."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {controls.map((c) => {
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
                <Button size="sm" variant="secondary" onClick={() => runControl(c)}>
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

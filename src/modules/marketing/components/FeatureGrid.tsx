import { Card, CardContent } from '@/shared/ui/core';
import type { MarketingFeature } from '../types/marketingTypes';

export function FeatureGrid({ features }: { features: readonly MarketingFeature[] }) {
  return (
    <section className="mx-auto max-w-7xl px-6 py-20">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {features.map((f) => (
          <Card key={f.title}>
            <CardContent className="space-y-2 px-5 py-6">
              <h3 className="text-base font-semibold text-foreground">
                {f.title}
              </h3>
              <p className="text-sm text-muted">{f.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}

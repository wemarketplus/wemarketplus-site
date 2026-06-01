import { Card, CardContent } from '@/shared/ui/core';
import type { ClinicalFeature } from '../types/clinicalTypes';
import { STATUS_LABEL, STATUS_TONE } from '../utils/clinicalUtils';

export function ClinicalFeatureCard({ feature }: { feature: ClinicalFeature }) {
  const Icon = feature.icon;
  return (
    <Card>
      <CardContent className="space-y-3 px-5 py-5">
        <div className="flex items-center justify-between">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
            <Icon className="h-5 w-5" />
          </div>
          <span
            className={`rounded-pill border px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] ${STATUS_TONE[feature.status]}`}
          >
            {STATUS_LABEL[feature.status]}
          </span>
        </div>
        <h2 className="text-base font-semibold text-foreground">{feature.title}</h2>
        <p className="text-sm text-muted">{feature.description}</p>
      </CardContent>
    </Card>
  );
}

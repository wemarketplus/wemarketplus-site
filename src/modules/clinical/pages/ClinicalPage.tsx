import { ClinicalFeatureCard } from '../components/ClinicalFeatureCard';
import { useClinicalFeatures } from '../hooks/useClinicalFeatures';

export function ClinicalPage() {
  const { features } = useClinicalFeatures();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Clinical workflows</h1>
        <p className="text-sm text-muted">
          Gold-tier features that connect marketing to the care team.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {features.map((f) => (
          <ClinicalFeatureCard key={f.id} feature={f} />
        ))}
      </div>
    </div>
  );
}

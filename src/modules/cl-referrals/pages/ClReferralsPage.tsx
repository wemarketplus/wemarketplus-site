import { ClReferralsTable } from '../components/ClReferralsTable';
import { useSeniorLivingReferrals } from '../hooks/useSeniorLivingReferrals';

export function ClReferralsPage() {
  const { referrals, isUsingFixture } = useSeniorLivingReferrals();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Referral sources</h1>
        <p className="text-sm text-muted">
          Family, physician, hospital, and community channels feeding your pipeline.
          {isUsingFixture && (
            <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
              Preview data
            </span>
          )}
        </p>
      </header>
      <ClReferralsTable items={referrals} />
    </div>
  );
}

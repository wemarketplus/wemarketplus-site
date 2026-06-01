import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/shared/ui/core';
import { ReferralsFilters } from '../components/ReferralsFilters';
import { ReferralsTable } from '../components/ReferralsTable';
import { useReferralsList } from '../hooks/useReferralsList';

export function ReferralsPage() {
  const { referrals, total, isUsingFixture } = useReferralsList();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Referral sources</h1>
          <p className="text-sm text-muted">
            {total} sources · the green ones drive your pipeline
            {isUsingFixture && (
              <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                Preview data
              </span>
            )}
          </p>
        </div>
        <Button onClick={() => toast.message('Add referral — form pending backend')}>
          <Plus className="h-4 w-4" /> Add source
        </Button>
      </header>

      <ReferralsFilters />
      <ReferralsTable items={referrals} />
    </div>
  );
}

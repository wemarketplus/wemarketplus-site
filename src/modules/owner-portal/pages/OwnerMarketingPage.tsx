import { Card, CardContent } from '@/shared/ui/core';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { formatMoney } from '../utils/ownerFormat';

const CHANNELS = [
  { id: 'google', label: 'Google Ads', spend: 8400, leads: 142, conversion: 0.18 },
  { id: 'linkedin', label: 'LinkedIn', spend: 5200, leads: 76, conversion: 0.11 },
  { id: 'partners', label: 'Partner referrals', spend: 0, leads: 38, conversion: 0.34 },
  { id: 'content', label: 'Content & SEO', spend: 1800, leads: 121, conversion: 0.09 },
];

export function OwnerMarketingPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Marketing performance"
        description="Spend, leads, and conversion by channel."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {CHANNELS.map((c) => (
          <Card key={c.id}>
            <CardContent className="space-y-2 px-5 py-5">
              <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
                {c.label}
              </p>
              <p className="font-display text-2xl leading-none text-foreground">
                {formatMoney(c.spend)} spend
              </p>
              <p className="text-xs text-muted">
                {c.leads} leads · {(c.conversion * 100).toFixed(0)}% close rate
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

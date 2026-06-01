import { Check } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import type { MarketingTierCard } from '../types/marketingTypes';
import { formatTierPrice } from '../utils/formatPrice';

export function TierCard({ card }: { card: MarketingTierCard }) {
  return (
    <Card
      className={cn(
        'relative flex flex-col',
        card.featured && 'border-primary/40 shadow-glow',
      )}
    >
      {card.featured && (
        <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-pill bg-primary px-3 py-0.5 text-[10px] font-bold uppercase tracking-[0.1em] text-primary-foreground">
          Most popular
        </span>
      )}
      <CardContent className="flex flex-1 flex-col gap-5 px-6 py-7">
        <div>
          <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
            {card.name}
          </p>
          <p className="mt-2 font-serif-display text-4xl leading-none text-foreground">
            {formatTierPrice(card)}
          </p>
          {card.bands && (
            <p className="mt-1.5 text-[11px] uppercase tracking-[0.08em] text-muted-soft">
              {card.bands}
            </p>
          )}
          <p className="mt-2 text-sm text-muted">{card.tagline}</p>
        </div>
        <ul className="mt-auto space-y-2 border-t border-white/[0.06] pt-4">
          {card.highlights.map((h) => (
            <li key={h} className="flex items-start gap-2 text-sm text-foreground">
              <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <span>{h}</span>
            </li>
          ))}
        </ul>
        <Link to="/onboarding">
          <Button className="w-full" variant={card.featured ? 'primary' : 'secondary'}>
            Start with {card.name.split(' ')[1] ?? 'this plan'}
          </Button>
        </Link>
      </CardContent>
    </Card>
  );
}

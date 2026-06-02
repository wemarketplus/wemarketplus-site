import {
  Activity,
  AlertCircle,
  Bot,
  DollarSign,
  FileText,
  LayoutGrid,
  Mic,
  Navigation,
  Phone,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { useScrollReveal } from '@/shared/hooks';
import { cn } from '@/shared/utils/cn';
import { revealClass, staggerStyle } from '@/shared/utils/scrollReveal';
import { SectionHeading } from '../SectionHeading';
import { HOSPICE_FEATURE_CARDS } from '../../constants/landingContent';
import { FEATURE_CARD_HOVER } from '../../constants/interactionConstants';
import type { FeatureCard, FeatureIcon } from '../../types/landingTypes';

// Icon-tile + badge tone per feature tone — mirrors the live #features grid.
const TONE_TILE: Record<FeatureCard['tone'], string> = {
  azure: 'bg-azure/15 text-azure',
  red: 'bg-[#e05555]/15 text-[#f87171]',
  sage: 'bg-sage/15 text-sage',
  purple: 'bg-[#6d28d9]/20 text-[#c9aeff]',
  amber: 'bg-amber/15 text-amber',
};

const BADGE_TONE: Record<FeatureCard['tone'], string> = {
  azure: 'border-azure/30 bg-azure/10 text-azure',
  red: 'border-[#e05555]/30 bg-[#e05555]/10 text-[#f87171]',
  sage: 'border-sage/30 bg-sage/10 text-sage',
  purple: 'border-[#c9aeff]/30 bg-[#6d28d9]/15 text-[#c9aeff]',
  amber: 'border-amber/30 bg-amber/10 text-amber',
};

const ICON: Record<FeatureIcon, LucideIcon> = {
  pipeline: FileText,
  alert: AlertCircle,
  map: Navigation,
  ai: Bot,
  mileage: LayoutGrid,
  windshield: Mic,
  revenue: DollarSign,
  triage: Activity,
  audit: ShieldCheck,
  phone: Phone,
};

// index.html #features — "Every Feature Your Team Needs", 3-col grid.
export function FeatureCards() {
  const { ref, visible } = useScrollReveal<HTMLElement>();

  return (
    <section ref={ref} id="features" className="mx-auto max-w-[1200px] px-7 py-20">
      <SectionHeading
        kicker="Built for Hospice"
        tone="sage"
        title="Every Feature Your Team Needs"
        className={revealClass(visible)}
      />
      {/* auto-rows-fr → every card shares one row height; h-full carries that
          equal height down to the Card so all cards are the same size. */}
      <div className="grid auto-rows-fr grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {HOSPICE_FEATURE_CARDS.map((f, i) => {
          const Icon = ICON[f.icon];
          return (
            // Reveal + stagger on the wrapper; hover lives on the Card so the
            // entrance animation and hover transform never compete.
            <div
              key={f.title}
              className={cn('h-full', revealClass(visible))}
              style={staggerStyle(i + 1, visible)}
            >
              <Card className={cn('h-full', FEATURE_CARD_HOVER)}>
                <CardContent className="space-y-0 p-6">
                  {/* icon tile — .feat-icon 38×38, r9 */}
                  <div
                    className={cn(
                      'mb-4 flex h-[38px] w-[38px] items-center justify-center rounded-[9px]',
                      TONE_TILE[f.tone],
                    )}
                  >
                    <Icon className="h-[19px] w-[19px]" strokeWidth={1.8} />
                  </div>
                  <h3 className="mb-2 text-[15px] font-bold tracking-[-0.01em] text-foreground">
                    {f.title}
                  </h3>
                  <p className="text-[13px] leading-[1.66] text-muted">{f.body}</p>
                  <span
                    className={cn(
                      'mt-3 inline-block rounded-pill px-2.5 py-[3px] text-[10px] font-bold uppercase tracking-[0.06em]',
                      BADGE_TONE[f.tone],
                    )}
                  >
                    {f.badge}
                  </span>
                </CardContent>
              </Card>
            </div>
          );
        })}
      </div>
    </section>
  );
}

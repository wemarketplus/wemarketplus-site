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
import { SectionHeading } from '../SectionHeading';
import { HOSPICE_FEATURE_CARDS } from '../../constants/landingContent';
import type { FeatureCard, FeatureIcon } from '../../types/landingTypes';
import { cn } from '@/shared/utils/cn';

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
  return (
    <section id="features" className="mx-auto max-w-[1200px] px-7 py-20">
      <SectionHeading kicker="Built for Hospice" tone="sage" title="Every Feature Your Team Needs" />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {HOSPICE_FEATURE_CARDS.map((f) => {
          const Icon = ICON[f.icon];
          return (
            <Card key={f.title}>
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
          );
        })}
      </div>
    </section>
  );
}

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
import {
  HOSPICE_FEATURE_CARDS,
  type FeatureCard,
  type FeatureIcon,
} from '../../constants/landingContent';
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
    <section id="features" className="mx-auto max-w-7xl px-6 py-20">
      <div className="mb-10 text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-sage">
          Built for Hospice
        </p>
        <h2 className="mt-3 font-serif-display text-3xl font-black text-foreground sm:text-4xl">
          Every Feature Your Team Needs
        </h2>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {HOSPICE_FEATURE_CARDS.map((f) => {
          const Icon = ICON[f.icon];
          return (
            <Card key={f.title}>
              <CardContent className="space-y-3 px-5 py-6">
                {/* icon tile */}
                <div
                  className={cn(
                    'flex h-9 w-9 items-center justify-center rounded-[10px]',
                    TONE_TILE[f.tone],
                  )}
                >
                  <Icon className="h-[18px] w-[18px]" strokeWidth={1.9} />
                </div>
                <h3 className="text-base font-bold text-foreground">{f.title}</h3>
                <p className="text-sm leading-relaxed text-muted">{f.body}</p>
                <span
                  className={cn(
                    'inline-block rounded-pill border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.06em]',
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

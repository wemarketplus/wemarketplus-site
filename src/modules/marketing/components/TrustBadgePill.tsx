import {
  Clock,
  Layers,
  Lock,
  Phone,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/shared/utils/cn';
import { TRUST_BADGE_ICON_TONE } from '../constants/interactionConstants';
import type { TrustBadge, TrustBadgeIcon } from '../types/landingTypes';

// index.html trust strip pill — a tone-coloured icon beside a title + caption,
// in a soft bordered chip. Icon key → component map lives here (components can
// reference other components); the tone→colour map is a constant.
const ICON: Record<TrustBadgeIcon, LucideIcon> = {
  shield: ShieldCheck,
  lock: Lock,
  guarantee: Layers,
  clock: Clock,
  phone: Phone,
};

export function TrustBadgePill({ badge }: { badge: TrustBadge }) {
  const Icon = ICON[badge.icon];
  return (
    <div className="flex items-center gap-2.5 rounded-[12px] border border-white/[0.08] bg-white/[0.03] px-4 py-2.5">
      <Icon
        className={cn('h-[18px] w-[18px] shrink-0', TRUST_BADGE_ICON_TONE[badge.tone])}
        strokeWidth={1.9}
        aria-hidden
      />
      <div className="text-left leading-tight">
        <p className="text-[13px] font-bold text-foreground">{badge.title}</p>
        <p className="text-[11px] text-faint">{badge.sub}</p>
      </div>
    </div>
  );
}

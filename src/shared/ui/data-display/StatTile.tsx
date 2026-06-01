import { cn } from '@/shared/utils/cn';

export type StatTone = 'b' | 'g' | 'gd' | 'r' | 'y';

interface StatTileProps {
  label: string;
  value: string;
  hint?: string;
  tone?: StatTone;
}

// Mirrors wemarketplus-site `.stat`: 12px radius, 14/16px padding, tinted
// fill + border per tone (rgba of the accent). Big value, small uppercase
// label, optional hint.
const TONE: Record<StatTone, string> = {
  b: 'border-[#49b6ff]/25 bg-[#49b6ff]/[0.1]',
  g: 'border-[#8cff66]/25 bg-[#8cff66]/[0.1]',
  gd: 'border-[#ffd700]/25 bg-[#ffd700]/[0.1]',
  r: 'border-[#e05555]/25 bg-[#e05555]/[0.1]',
  y: 'border-[#fbbf24]/25 bg-[#fbbf24]/[0.1]',
};

const VALUE_TONE: Record<StatTone, string> = {
  b: 'text-[#79c0ff]',
  g: 'text-[#8cff66]',
  gd: 'text-[#ffd700]',
  r: 'text-[#f87171]',
  y: 'text-[#fbbf24]',
};

export function StatTile({ label, value, hint, tone = 'b' }: StatTileProps) {
  return (
    <div className={cn('rounded-[12px] border px-4 py-3.5', TONE[tone])}>
      <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-muted-soft">
        {label}
      </p>
      <p className={cn('mt-1.5 text-[26px] font-black leading-none', VALUE_TONE[tone])}>
        {value}
      </p>
      {hint && <p className="mt-1.5 text-[11px] text-muted">{hint}</p>}
    </div>
  );
}

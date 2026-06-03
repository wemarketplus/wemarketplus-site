import { cn } from '@/shared/utils/cn';
import { STAT, STAT_LABEL, STAT_SUB, STAT_VALUE } from '../styles';

interface StatTileProps {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  // Tone overrides reproduce .sg/.sr/.sa on the value/sub.
  valueClassName?: string;
  subClassName?: string;
  onClick?: () => void;
}

// Reproduces the reference .stat tile (.sl / .sv / .ss).
export function StatTile({
  label,
  value,
  sub,
  valueClassName,
  subClassName,
  onClick,
}: StatTileProps) {
  return (
    <div
      className={cn(STAT, !onClick && 'cursor-default')}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
    >
      <div className={STAT_LABEL}>{label}</div>
      <div className={cn(STAT_VALUE, valueClassName)}>{value}</div>
      {sub != null && <div className={cn(STAT_SUB, subClassName)}>{sub}</div>}
    </div>
  );
}

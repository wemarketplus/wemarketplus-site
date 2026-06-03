import { cn } from '@/shared/utils/cn';
import { FL, FLB, FW } from '../styles';

interface FieldProps {
  label: string;
  // Spans the full grid width (.fw) — used for notes/textarea rows.
  wide?: boolean;
  children: React.ReactNode;
  className?: string;
}

// Reproduces the reference .fl wrapper: a small label (.flb) above its control.
export function Field({ label, wide = false, children, className }: FieldProps) {
  return (
    <div className={cn(FL, wide && FW, className)}>
      <div className={FLB}>{label}</div>
      {children}
    </div>
  );
}

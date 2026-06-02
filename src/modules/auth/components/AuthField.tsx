import { Label } from '@/shared/ui/core';
import type { AuthFieldProps } from '../types/authTypes';

// Mirrors wemarketplus-site `.field`: label + control + 16px bottom margin.
export function AuthField({ label, htmlFor, error, children, helper }: AuthFieldProps) {
  return (
    <div className="mb-4">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {helper && <div className="mt-1.5 text-right">{helper}</div>}
      {error && <p className="mt-1.5 text-[12px] text-destructive">{error}</p>}
    </div>
  );
}

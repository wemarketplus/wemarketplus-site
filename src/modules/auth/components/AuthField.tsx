import type { ReactNode } from 'react';
import { Label } from '@/shared/ui/core';

interface AuthFieldProps {
  label: string;
  htmlFor: string;
  error?: string;
  children: ReactNode;
  // Optional right-aligned helper under the input (e.g. "Forgot password?").
  helper?: ReactNode;
}

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

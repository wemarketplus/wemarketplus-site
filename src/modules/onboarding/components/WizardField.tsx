import type { ReactNode } from 'react';
import { Label } from '@/shared/ui/core';

interface WizardFieldProps {
  label: string;
  htmlFor: string;
  error?: string;
  children: ReactNode;
}

// Tiny labelled-field wrapper used across wizard step forms. Extracted so
// no step component has to define its own local layout helper.
export function WizardField({ label, htmlFor, error, children }: WizardFieldProps) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

import type { ReactNode } from 'react';

// Mirrors wemarketplus-site `.err`: red-tinted box, only rendered when there's
// a message (the source toggles display:none).
export function AuthError({ children }: { children?: ReactNode }) {
  if (!children) return null;
  return (
    <div className="mb-4 rounded-[10px] border border-[#e05555]/40 bg-[#e05555]/[0.12] px-3.5 py-2.5 text-[13px] text-destructive">
      {children}
    </div>
  );
}

import type { ReactNode } from 'react';

interface SectionHeaderProps {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}

// Mirrors wemarketplus-site `.sec-hdr`: 22px/900 title, 12px muted subtitle,
// optional right-aligned actions, 14px bottom margin.
//
// `text-foreground`, not `text-white`. The title was white — a leftover from the
// dark canvas this component was first drawn on — which on the light theme the app
// actually ships is white-on-white: the heading rendered, took up its space, and
// was invisible. It was the only `text-white` left in shared/ui. Every consumer
// (the two Executive Dashboard cards and the three Intelligence pages) had a blank
// gap where its title should be.
export function SectionHeader({ title, subtitle, actions }: SectionHeaderProps) {
  return (
    <div className="mb-3.5 flex items-center justify-between gap-4">
      <div>
        <h2 className="text-[22px] font-black leading-tight text-foreground">{title}</h2>
        {subtitle && <p className="mt-0.5 text-[12px] text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

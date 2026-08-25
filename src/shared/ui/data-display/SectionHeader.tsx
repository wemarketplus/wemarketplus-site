import type { ReactNode } from 'react';
import { SECTION_SUBTITLE, SECTION_TITLE } from '@/shared/ui/core/typography';

interface SectionHeaderProps {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}

// Mirrors wemarketplus-site `.sec-hdr`: optional right-aligned actions, 14px
// bottom margin. Type comes from SECTION_TITLE/SECTION_SUBTITLE.
//
// It was 22px/900, which is LARGER and HEAVIER than <CardTitle>'s 18px/800 for
// the same job, and only 8px off the 30px page title it always sits beneath —
// so a section heading competed with the name of the screen. That was one of
// four competing answers to "what does a section heading look like": this
// component, CardTitle, and 34 hand-rolled h2s split between `text-sm
// font-semibold` and `text-base font-semibold`. Two of the four shipped from
// shared/ui, which is why the drift spread. This and CardTitle now resolve to
// the same constant.
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
        <h2 className={SECTION_TITLE}>{title}</h2>
        {subtitle && <p className={`mt-0.5 ${SECTION_SUBTITLE}`}>{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

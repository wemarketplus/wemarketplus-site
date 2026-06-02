import { Home } from 'lucide-react';
import { useScrollReveal } from '@/shared/hooks';
import { cn } from '@/shared/utils/cn';
import { revealClass } from '@/shared/utils/scrollReveal';

// index.html .origin-card — azure-gradient callout with an azure→sage avatar
// and an azure "Built by Hospice Operators" label.
export function OriginStory() {
  const { ref, visible } = useScrollReveal<HTMLElement>();

  return (
    <section ref={ref} className="mx-auto max-w-[1200px] px-7 py-20">
      <div
        className={cn(
          'grid grid-cols-1 items-center gap-[30px] rounded-[22px] border border-azure/[0.22] bg-[linear-gradient(135deg,rgba(61,158,232,0.06),rgba(18,31,61,0.4))] p-10 sm:grid-cols-[auto_1fr]',
          revealClass(visible),
        )}
      >
        <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-[16px] bg-[linear-gradient(135deg,#3d9ee8,#4fc87a)] text-[#06080e]">
          <Home className="h-7 w-7" strokeWidth={2} />
        </div>
        <div>
          <div className="mb-2 text-[11px] font-bold uppercase tracking-[0.1em] text-azure">
            Built by Hospice Operators
          </div>
          <h3 className="mb-[10px] font-serif-display text-[20px] leading-[1.2] text-foreground">
            20+ Years in Hospice &amp; Senior Living Sales
          </h3>
          <p className="text-[14px] leading-[1.74] text-muted">
            HospiceLink was not built by software engineers guessing what hospice
            teams need. It was built by industry veterans who have personally
            worked referral relationships, sat in IDT meetings, managed census
            goals, and felt the pain of spreadsheet chaos. Every feature exists
            because someone on our team needed it in the field.
          </p>
        </div>
      </div>
    </section>
  );
}

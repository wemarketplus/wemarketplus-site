import type { LegalBlock } from '../types/legalTypes';

// Renders the structured legal copy (headings, paragraphs, bullet lists,
// callouts) inside a LegalShell card.
export function LegalBlocks({ blocks }: { blocks: readonly LegalBlock[] }) {
  return (
    <div className="space-y-6">
      {blocks.map((b, i) => (
        <div key={b.heading ?? i} className="space-y-2">
          {b.heading && (
            <h2 className="text-[15px] font-bold text-foreground">{b.heading}</h2>
          )}
          {b.callout && (
            <div className="rounded-[12px] border border-azure/20 bg-azure/[0.07] p-4">
              <p className="mb-1 text-[13px] font-bold text-azure">
                {b.callout.title}
              </p>
              <p className="text-[13px] leading-relaxed text-muted">
                {b.callout.body}
              </p>
            </div>
          )}
          {b.paragraphs?.map((p, j) => (
            <p key={j} className="text-[13px] leading-relaxed text-muted">
              {p}
            </p>
          ))}
          {b.list && (
            <ul className="list-disc space-y-1 pl-5 text-[13px] leading-relaxed text-muted">
              {b.list.map((li, k) => (
                <li key={k}>{li}</li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

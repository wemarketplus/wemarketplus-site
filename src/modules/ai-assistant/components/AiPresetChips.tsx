import { AI_PRESETS } from '../constants/aiPresetsConstants';
import type { AiPresetChipsProps } from '../types/aiAssistantTypes';

export function AiPresetChips({ onPick }: AiPresetChipsProps) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {AI_PRESETS.map((p) => (
        <button
          key={p.id}
          type="button"
          onClick={() => onPick(p.prompt)}
          className="rounded-pill border border-border/[0.08] bg-foreground/[0.02] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted transition-colors hover:border-border/20 hover:text-foreground"
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}

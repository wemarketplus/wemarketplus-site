import { AI_PRESETS } from '../constants/aiPresetsConstants';

export function AiPresetChips({ onPick }: { onPick: (prompt: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {AI_PRESETS.map((p) => (
        <button
          key={p.id}
          type="button"
          onClick={() => onPick(p.prompt)}
          className="rounded-pill border border-white/[0.08] bg-white/[0.02] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted transition-colors hover:border-white/20 hover:text-foreground"
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}

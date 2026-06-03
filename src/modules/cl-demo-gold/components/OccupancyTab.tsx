import { APT_STATUS_COLORS, APT_STATUS_LABELS } from '../constants/goldStatus';
import { useGoldDemo } from '../hooks/useGoldDemo';

// Reproduces rOccupancy(): a responsive grid of unit cards, each tinted by its
// status, linking through to the apartment inventory.
export function OccupancyTab() {
  const { apts, actions } = useGoldDemo();

  return (
    <div className="grid gap-3 [grid-template-columns:repeat(auto-fill,minmax(160px,1fr))]">
      {apts.map((a) => {
        const color = APT_STATUS_COLORS[a.status];
        return (
          <div
            key={a.id}
            role="button"
            onClick={() => actions.setTab('apartments')}
            className="cursor-pointer rounded-[12px] bg-[#071120] p-[14px]"
            style={{ border: `1px solid ${color}33` }}
          >
            <div className="mb-2 flex items-center justify-between">
              <div className="text-[18px] font-black text-[#f4f8ff]">Unit {a.unit}</div>
              <span
                className="inline-block rounded-full px-2 py-0.5 text-[10px] font-bold"
                style={{ background: `${color}20`, color }}
              >
                {APT_STATUS_LABELS[a.status]}
              </span>
            </div>
            <div className="text-[11px] text-[#6b7fa3]">{a.type} • {a.care}</div>
            <div className="mt-1 text-[11px] text-[#c8d6e8]">{a.resident || 'Vacant'}</div>
            {a.rate > 0 && (
              <div className="mt-0.5 text-[11px] text-[#4fc87a]">${a.rate.toLocaleString()}/mo</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

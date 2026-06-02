// Single item in the live-activity ticker strip (see ActivityTicker).
export function TickerItem({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="inline-flex items-center gap-2 whitespace-nowrap"
      style={{ padding: '0 28px', fontSize: 13, color: '#888' }}
    >
      <span
        className="inline-block shrink-0 rounded-full"
        style={{ width: 5, height: 5, background: color }}
        aria-hidden="true"
      />
      {label}
    </span>
  );
}

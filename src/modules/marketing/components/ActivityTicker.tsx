import { TICKER_ITEMS } from '../constants/marketingConstants';
import { TickerItem } from './TickerItem';

export function ActivityTicker() {
  return (
    <div
      className="ticker-wrap border-b"
      style={{ background: '#06080e', borderColor: '#222', height: 36 }}
      aria-label="Live activity feed"
    >
      <div className="ticker-track" style={{ alignItems: 'center', height: '100%' }}>
        {TICKER_ITEMS.map((item) => (
          <TickerItem key={item.label} label={item.label} color={item.color} />
        ))}
        {/* Duplicate set for seamless infinite loop */}
        {TICKER_ITEMS.map((item) => (
          <TickerItem
            key={`dup-${item.label}`}
            label={item.label}
            color={item.color}
          />
        ))}
      </div>
    </div>
  );
}

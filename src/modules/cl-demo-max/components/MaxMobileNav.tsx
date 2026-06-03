import { useState } from 'react';
import { cn } from '@/shared/utils/cn';
import { MOBILE_BOTTOM_NAV, NAV } from '../constants/maxNav';
import { useMaxDemo } from '../hooks/useMaxDemo';
import type { ModalKey } from '../types/maxTypes';

const QUICK: Array<{ label: string; run: (a: ReturnType<typeof useMaxDemo>['actions']) => void }> = [
  { label: 'Add Lead', run: (a) => a.openModal('addLead' as ModalKey) },
  { label: 'Add Note', run: (a) => a.setTab('notes') },
  { label: 'New Ticket', run: (a) => a.openModal('addTicket' as ModalKey) },
  { label: 'Log Mileage', run: (a) => a.setTab('mileage') },
];

// Reproduces the reference mobile bottom nav (#mobile-nav), slide-out "All
// Modules" menu, and the quick-add FAB. Visible only below 640px (sm).
export function MaxMobileNav() {
  const { role, activeTab, actions } = useMaxDemo();
  const [menuOpen, setMenuOpen] = useState(false);
  const [fabOpen, setFabOpen] = useState(false);

  return (
    <>
      {/* Quick-add FAB */}
      <div className="fixed bottom-[72px] right-4 z-[999] flex flex-col items-end gap-2 sm:hidden">
        {fabOpen && QUICK.map((q) => (
          <button key={q.label} type="button" onClick={() => { q.run(actions); setFabOpen(false); }} className="whitespace-nowrap rounded-full border border-[#f59e0b]/30 bg-[#0a1628] px-4 py-2 text-[12px] font-bold text-[#f59e0b] shadow-[0_2px_12px_rgba(0,0,0,.4)]">{q.label}</button>
        ))}
        <button type="button" onClick={() => setFabOpen((o) => !o)} className="flex h-[52px] w-[52px] items-center justify-center rounded-full bg-[#f59e0b] text-[24px] text-[#06080e] shadow-[0_4px_16px_rgba(245,158,11,.4)]">+</button>
      </div>

      {/* Bottom nav */}
      <div className="fixed bottom-0 left-0 right-0 z-[1000] flex h-[58px] border-t border-white/[0.08] bg-[#0a1628] shadow-[0_-2px_20px_rgba(0,0,0,.35)] sm:hidden">
        {MOBILE_BOTTOM_NAV.map((b) => (
          <button key={b.key} type="button" onClick={() => actions.setTab(b.key)} className={cn('flex flex-1 flex-col items-center justify-center gap-0.5 border-t-2 px-0.5 py-1 text-[9px] font-extrabold uppercase tracking-[0.03em]', activeTab === b.key ? 'border-[#f59e0b] bg-[#f59e0b]/[0.06] text-[#f59e0b]' : 'border-transparent text-[#6b7fa3]')}>
            <span className="text-[19px] leading-none">{b.icon}</span>
            <span className="w-full truncate text-center text-[8px]">{b.label}</span>
          </button>
        ))}
        <button type="button" onClick={() => setMenuOpen(true)} className="flex flex-1 flex-col items-center justify-center gap-0.5 border-t-2 border-transparent px-0.5 py-1 text-[9px] font-extrabold uppercase tracking-[0.03em] text-[#6b7fa3]">
          <span className="text-[19px] leading-none">☰</span>
          <span className="text-[8px]">Menu</span>
        </button>
      </div>

      {/* Slide-out menu */}
      {menuOpen && <div className="fixed inset-0 z-[2000] bg-black/60 sm:hidden" onClick={() => setMenuOpen(false)} />}
      <div className={cn('fixed bottom-0 left-0 top-0 z-[2001] w-[290px] overflow-y-auto border-r border-white/[0.08] bg-[#0a1628] transition-transform duration-[280ms] sm:hidden', menuOpen ? 'translate-x-0' : '-translate-x-full')}>
        <div className="sticky top-0 z-[1] flex items-center justify-between border-b border-white/[0.07] bg-[#0a1628] px-4 pb-3 pt-5">
          <div>
            <div className="text-[15px] font-black text-[#f4f8ff]">All Modules</div>
            <div className="mt-px text-[10px] text-[#6b7fa3]">Tap any section to navigate</div>
          </div>
          <button type="button" onClick={() => setMenuOpen(false)} className="flex h-9 w-9 items-center justify-center rounded-full bg-white/[0.04] text-[22px] text-[#6b7fa3]">×</button>
        </div>
        <div className="px-2 pb-20 pt-2.5">
          {NAV[role].map((sec) => (
            <div key={sec.sec} className="mb-1">
              <div className="px-2 pb-1 pt-2 text-[9px] font-black uppercase tracking-[0.1em] text-[#4b6278]">{sec.sec}</div>
              {sec.items.map((item) => (
                <button key={item.k} type="button" onClick={() => { actions.setTab(item.k); setMenuOpen(false); }} className="block w-full rounded-[8px] px-3 py-2.5 text-left text-[13px] text-[#c8d6e8] hover:bg-white/[0.06]">{item.l}</button>
              ))}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

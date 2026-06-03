import { cn } from '@/shared/utils/cn';
import { NAV, ROLE_LABELS, ROLE_OPTIONS } from '../constants/maxNav';
import { useMaxDemo } from '../hooks/useMaxDemo';
import type { MaxRole } from '../types/maxTypes';

// Reproduces the reference <aside class="sb">: 224px column, brand block (green
// "Max CRM Demo" tier), DEMO badge, "Viewing As" role <select> (7 roles),
// role-based nav, and footer. Hidden below 640px (mobile uses the bottom nav).
export function MaxSidebar() {
  const { role, activeTab, actions } = useMaxDemo();

  return (
    <aside className="hidden h-screen w-[224px] min-w-[224px] flex-col overflow-hidden border-r border-white/[0.08] bg-[#060e1b] sm:flex">
      <div className="flex-shrink-0 px-3 pb-2.5 pt-3.5">
        <div className="mb-2.5 flex items-center gap-[9px]">
          <div className="flex h-[30px] w-[30px] flex-shrink-0 items-center justify-center rounded-[8px] bg-gradient-to-br from-[#f59e0b] to-[#d97706]">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#06080e" strokeWidth="2.5">
              <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
              <polyline points="9 22 9 12 15 12 15 22" />
            </svg>
          </div>
          <div>
            <div className="text-[13px] font-black text-[#f4f8ff]">CommunityLink</div>
            <div className="text-[9px] font-extrabold uppercase tracking-[0.08em] text-[#4fc87a]">Max CRM Demo</div>
          </div>
        </div>

        <div className="mb-2 rounded-[8px] border border-[#f59e0b]/20 bg-[#f59e0b]/10 px-2.5 py-1.5 text-center text-[11px] font-bold text-[#f59e0b]">
          DEMO MODE — No Login Required
        </div>

        <div className="mb-1.5 rounded-[10px] border border-[#f59e0b]/[0.12] bg-[#f59e0b]/[0.05] px-[11px] py-[9px]">
          <div className="mb-[5px] text-[9px] font-extrabold uppercase tracking-[0.1em] text-[#4b6278]">Viewing As</div>
          <select
            value={role}
            onChange={(e) => actions.setRole(e.target.value as MaxRole)}
            className="w-full cursor-pointer rounded-[7px] border border-white/10 bg-[#0a1628] px-[9px] py-1.5 text-[12px] font-bold text-[#f0f5ff] outline-none"
          >
            {ROLE_OPTIONS.map((r) => (
              <option key={r} value={r}>{ROLE_LABELS[r]}</option>
            ))}
          </select>
          <div className="mt-[5px] inline-block rounded-full border border-[#f59e0b]/20 bg-[#f59e0b]/15 px-2.5 py-0.5 text-[10px] font-extrabold text-[#f59e0b]">
            {ROLE_LABELS[role]}
          </div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 pb-2" aria-label="Demo navigation">
        {NAV[role].map((group) => (
          <div key={group.sec}>
            <span className="block px-1.5 pb-[3px] pt-2.5 text-[9px] font-black uppercase tracking-[0.12em] text-[#1e3a5f]">{group.sec}</span>
            {group.items.map((item) => (
              <button
                key={item.k}
                type="button"
                onClick={() => actions.setTab(item.k)}
                className={cn(
                  'mb-px block w-full truncate rounded-[8px] px-2.5 py-[7px] text-left text-[12px] font-semibold transition-colors',
                  activeTab === item.k
                    ? 'bg-[#f59e0b]/[0.12] font-extrabold text-[#f59e0b]'
                    : 'text-[#7a9abf] hover:bg-white/[0.06] hover:text-[#c8d6e8]',
                )}
              >
                {item.l}
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div className="flex-shrink-0 border-t border-white/[0.07] px-3 py-2.5 text-center text-[10px]">
        <a href="/communitylink" className="font-bold text-[#f59e0b] no-underline">← Back to the Website</a>
      </div>
    </aside>
  );
}

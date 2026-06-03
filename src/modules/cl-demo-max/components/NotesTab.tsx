import { useMemo, useState } from 'react';
import { Badge, Card, DemoButton, FI } from '@/shared/cl-demo';
import {
  COMM_META,
  CONTACT_TYPE_TONE,
  ENTERED_BY_USERS,
  NOTE_NEXT_STEPS,
  NOTE_OUTCOMES,
  NOTE_STAGES,
  NOTE_TYPES,
  ROLE_USER_NAMES,
} from '../constants/maxNotes';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { buildContactOptions } from '../utils/maxFormat';
import { Fld } from './Fld';
import type { BadgeTone } from '@/shared/cl-demo';
import type { ContactOpt } from '../types/maxTypes';

// Reproduces rNotes(): the add-note form with a searchable contact typeahead
// and the unified activity timeline.
export function NotesTab() {
  const { leads, paidRefsPortal, notes, role, actions } = useMaxDemo();
  const now = new Date();
  const currentUser = ROLE_USER_NAMES[role] || role;
  const dateStr = now.toLocaleDateString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' });
  const timeStr = now.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
  const suggestDate = new Date(now.getTime() + 2 * 86400000).toISOString().split('T')[0];

  const contacts = useMemo(() => buildContactOptions(leads, paidRefsPortal), [leads, paidRefsPortal]);

  const [enteredBy, setEnteredBy] = useState('auto');
  const [contactQ, setContactQ] = useState('');
  const [contactName, setContactName] = useState('');
  const [ddOpen, setDdOpen] = useState(false);
  const [type, setType] = useState('manual');
  const [summary, setSummary] = useState('');
  const [outcome, setOutcome] = useState('');
  const [nextSel, setNextSel] = useState('');
  const [nextTxt, setNextTxt] = useState('');
  const [followDate, setFollowDate] = useState(suggestDate);
  const [stage, setStage] = useState('');
  const [filter, setFilter] = useState('');

  const q = contactQ.toLowerCase().trim();
  const matches = contacts.filter((c) => !q || c.name.toLowerCase().includes(q) || c.type.toLowerCase().includes(q));

  const selectContact = (c: ContactOpt) => { setContactName(c.name); setContactQ(c.name); setDdOpen(false); };

  const save = () => {
    if (!summary.trim()) { actions.toast('Summary is required', true); return; }
    const nextStep = nextSel && nextSel !== 'Other — type below' ? nextSel : nextTxt;
    const author = enteredBy === 'auto' ? currentUser : enteredBy;
    actions.addNote({ id: 0, type: 'manual', comm_type: type, contact_name: contactName || contactQ, summary: summary.trim(), outcome, next_step: nextStep, follow_up_date: followDate || null, stage, created_at: new Date().toISOString(), user_name: author });
    setSummary(''); setOutcome(''); setNextTxt(''); setNextSel(''); setContactName(''); setContactQ('');
  };

  const filtered = notes.filter((n) => !filter || n.comm_type === filter || n.type === filter);

  return (
    <>
      <Card title="+ Add Activity Note" action={<div className="flex items-center gap-2 text-[11px] text-[#6b7fa3]">🕐 Auto-logged at <strong className="text-[#f59e0b]">{dateStr} {timeStr}</strong></div>}>
        <div className="flex flex-col gap-2.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-[11px] text-[#6b7fa3]">Entered by:</span>
            <select className={`${FI} w-[240px] !py-1.5`} value={enteredBy} onChange={(e) => setEnteredBy(e.target.value)}>
              <option value="auto">{currentUser} (current user)</option>
              {ENTERED_BY_USERS.map((u) => <option key={u} value={u}>{u}</option>)}
            </select>
            <span className="text-[10px] text-[#4b6278]">Aircall notes are auto-tagged — do not manually select Aircall</span>
          </div>

          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            <div>
              <div className="mb-1 text-[11px] font-bold uppercase tracking-[0.04em] text-[#8ba4c4]">Added By <span className="text-[9px] font-normal text-[#4fc87a]">(auto)</span></div>
              <div className="flex items-center gap-2 rounded-[8px] border border-[#4fc87a]/25 bg-[#060e1b] px-3 py-[9px]">
                <div className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-[#f59e0b]/20 text-[13px] font-black text-[#f59e0b]">{currentUser.charAt(0).toUpperCase()}</div>
                <div><div className="text-[13px] font-bold text-[#f4f8ff]">{currentUser}</div><div className="text-[10px] text-[#4b6278]">{role.charAt(0).toUpperCase() + role.slice(1)}</div></div>
              </div>
            </div>
            <div>
              <div className="mb-1 text-[11px] font-bold uppercase tracking-[0.04em] text-[#8ba4c4]">Date &amp; Time <span className="text-[9px] font-normal text-[#4fc87a]">(auto)</span></div>
              <div className="flex items-center gap-2 rounded-[8px] border border-[#4fc87a]/25 bg-[#060e1b] px-3 py-[9px]">
                <span className="text-[18px]">🕐</span>
                <div><div className="text-[13px] font-bold text-[#f4f8ff]">{dateStr}</div><div className="text-[11px] text-[#4b6278]">{timeStr}</div></div>
              </div>
            </div>
          </div>

          <div className="relative">
            <div className="mb-1 text-[11px] font-bold uppercase tracking-[0.04em] text-[#8ba4c4]">Contact / Lead / Referral <span className="text-[9px] text-[#f87171]">Who is this note about?</span></div>
            <input
              className="w-full rounded-[8px] border-2 border-white/10 bg-[#060e1b] px-3 py-2.5 text-[13px] text-[#f4f8ff] outline-none focus:border-[#f59e0b]/50"
              placeholder="Start typing a name — leads, referrals, contacts appear…"
              value={contactQ}
              onChange={(e) => { setContactQ(e.target.value); setContactName(''); setDdOpen(true); }}
              onFocus={() => setDdOpen(true)}
              onBlur={() => setTimeout(() => setDdOpen(false), 200)}
            />
            {ddOpen && (
              <div className="absolute left-0 right-0 top-[calc(100%+4px)] z-[9999] max-h-[260px] overflow-y-auto rounded-[10px] border border-[#f59e0b]/30 bg-[#0d1e35] shadow-[0_8px_32px_rgba(0,0,0,.4)]">
                {matches.map((c) => (
                  <div key={c.id} onMouseDown={() => selectContact(c)} className="flex cursor-pointer items-start gap-2.5 border-b border-white/[0.05] px-3.5 py-2.5 hover:bg-white/[0.05]">
                    <Badge tone={(CONTACT_TYPE_TONE[c.type] || 'green') as BadgeTone}>{c.type}</Badge>
                    <div className="min-w-0 flex-1">
                      <div className="text-[13px] font-bold text-[#f4f8ff]">{c.name}{(c.urgency === 'Hot' || c.urgency === 'hot') && <span className="ml-1 rounded-full bg-[#f87171]/10 px-1.5 py-px text-[9px] font-black text-[#f87171]">HOT</span>}</div>
                      <div className="mt-px text-[11px] text-[#6b7fa3]">{c.sub}</div>
                    </div>
                  </div>
                ))}
                {q && matches.length === 0 && (
                  <div onMouseDown={() => { setContactName(contactQ); setDdOpen(false); actions.toast('New contact "' + contactQ + '" will be saved with this note'); }} className="cursor-pointer border-t border-white/[0.06] bg-white/[0.02] px-3.5 py-2.5 text-[12px] text-[#6b7fa3] hover:bg-white/[0.05]">
                    <span className="text-[14px]">+</span> Add &ldquo;{contactQ}&rdquo; as a new contact
                  </div>
                )}
              </div>
            )}
          </div>

          <Fld label="Note Type"><select className={FI} value={type} onChange={(e) => setType(e.target.value)}>{NOTE_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}</select></Fld>
          <Fld label="Summary *"><textarea className={`${FI} min-h-[72px]`} rows={3} placeholder="What happened? What was discussed? Emotional tone? Key points raised…" value={summary} onChange={(e) => setSummary(e.target.value)} /></Fld>
          <Fld label="Outcome"><select className={FI} value={outcome} onChange={(e) => setOutcome(e.target.value)}><option value="">Select outcome…</option>{NOTE_OUTCOMES.map((o) => <option key={o}>{o}</option>)}</select></Fld>
          <Fld label="Next Step — select or type your own">
            <select className={FI} value={nextSel} onChange={(e) => setNextSel(e.target.value)}><option value="">Select next step…</option>{NOTE_NEXT_STEPS.map((n) => <option key={n}>{n}</option>)}</select>
            <input className={`${FI} mt-1.5`} placeholder="Or type a custom next step…" value={nextTxt} onChange={(e) => setNextTxt(e.target.value)} />
          </Fld>
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            <Fld label="Follow-Up Date"><input className={FI} type="date" value={followDate} onChange={(e) => setFollowDate(e.target.value)} /></Fld>
            <Fld label="Pipeline Stage at Time of Note"><select className={FI} value={stage} onChange={(e) => setStage(e.target.value)}><option value="">— Select stage —</option>{NOTE_STAGES.map((s) => <option key={s}>{s}</option>)}</select></Fld>
          </div>
          <DemoButton className="mt-1 px-6 py-[11px] text-[14px]" onClick={save}>💾 Save Note</DemoButton>
        </div>
      </Card>

      <div className="mb-2.5 flex items-center justify-between">
        <div className="text-[13px] font-extrabold text-[#f4f8ff]">Activity Timeline <span className="font-normal text-[#4b6278]">({notes.length} entries)</span></div>
        <select className={`${FI} w-[150px]`} value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">All Types</option>
          <option value="call">📞 Calls</option><option value="text">💬 Texts</option><option value="email">✉️ Emails</option><option value="missed_call">📵 Missed Calls</option><option value="visit">🤝 Visits</option><option value="manual">📝 Manual Notes</option>
        </select>
      </div>

      {filtered.length === 0 ? (
        <Card><div className="px-2 py-6 text-center text-[13px] text-[#4b6278]">No activity yet. Every call, text, email, and manual note appears here in one unified timeline.</div></Card>
      ) : (
        filtered.map((n) => {
          const meta = COMM_META[n.comm_type] || COMM_META.manual;
          const ts = n.created_at ? new Date(n.created_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '';
          const cleanSummary = (n.summary || '').replace(/^[^\]]+\]\s*/, '');
          return (
            <div key={n.id} className="mb-2.5 rounded-[12px] bg-[#0a1628] px-4 py-3.5" style={{ border: `1px solid ${meta.border}` }}>
              <div className="mb-2 flex flex-wrap items-start justify-between gap-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full px-2.5 py-[3px] text-[11px] font-extrabold" style={{ background: meta.bg, border: `1px solid ${meta.border}`, color: meta.color }}>{meta.icon} {meta.label}</span>
                  {(n.contact_name || n.prospect_name) && <span className="text-[12px] font-bold text-[#f4f8ff]">{n.contact_name || n.prospect_name}</span>}
                  {n.stage && <span className="rounded-[4px] bg-white/[0.04] px-1.5 py-px text-[10px] text-[#6b7fa3]">{n.stage}</span>}
                </div>
                <span className="whitespace-nowrap text-[11px] text-[#6b7fa3]">{ts}</span>
              </div>
              {cleanSummary && <div className="mb-1.5 text-[13px] leading-[1.5] text-[#c8d6e8]">{cleanSummary}</div>}
              {n.outcome && <div className="mb-1 text-[12px] text-[#8ba4c4]"><span className="font-bold text-[#c8d6e8]">Outcome:</span> {n.outcome}</div>}
              {n.next_step && <div className="mb-1 text-[12px] text-[#8ba4c4]"><span className="font-bold text-[#f59e0b]">Next Step:</span> {n.next_step}</div>}
              {n.follow_up_date && <div className="mb-1 text-[12px] text-[#8ba4c4]"><span className="font-bold text-[#4fc87a]">Follow-Up:</span> {n.follow_up_date}</div>}
              <div className="mt-1.5 flex items-center gap-1.5 border-t border-white/[0.06] pt-1.5">
                {n.type === 'aircall'
                  ? <span className="rounded-[4px] border border-[#3d9ee8]/30 bg-[#3d9ee8]/15 px-2 py-0.5 text-[10px] font-black text-[#49b6ff]">AIRCALL</span>
                  : <span className="rounded-full bg-[#f59e0b]/10 px-2 py-px text-[10px] font-extrabold text-[#f59e0b]">{n.user_name || currentUser}</span>}
              </div>
            </div>
          );
        })
      )}
    </>
  );
}

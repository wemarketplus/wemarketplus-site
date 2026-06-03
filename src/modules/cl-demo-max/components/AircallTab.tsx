import { useEffect, useRef, useState } from 'react';
import { Card, DemoButton, Field, FI } from '@/shared/cl-demo';
import { cn } from '@/shared/utils/cn';
import { AC_EMAIL_TPL, AC_TEXT_TPL } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { aircallToneCls, composeAircallSummary } from '../utils/maxFormat';
import type { Channel } from '../types/maxTypes';

const CH_BTN = 'rounded-full border border-white/[0.09] bg-white/[0.05] px-[18px] py-[7px] text-[12px] font-bold text-[#8ba4c4] transition-colors';
const CH_ON = 'border-transparent bg-gradient-to-br from-[#f59e0b] to-[#d97706] text-[#06080e]';

// Reproduces rAircall(): channel switcher with Call (live dialer sim), Text,
// and Email panels — each logging activity to the Notes timeline.
export function AircallTab() {
  const { actions } = useMaxDemo();
  const [ch, setCh] = useState<Channel>('call');

  // Call state
  const [callContact, setCallContact] = useState('');
  const [callPhone, setCallPhone] = useState('');
  const [live, setLive] = useState(false);
  const [secs, setSecs] = useState(0);
  const [muted, setMuted] = useState(false);
  const timer = useRef<number | null>(null);
  const [callOutcome, setCallOutcome] = useState('');
  const [callNext, setCallNext] = useState('');
  const [callFollow, setCallFollow] = useState('');
  const [callSummary, setCallSummary] = useState('');

  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); }, []);

  const callName = callContact ? callContact.split('|')[0] : callPhone || 'Contact';
  const startCall = () => {
    if (!callPhone) { actions.toast('Enter a phone number first', true); return; }
    actions.toast('📞 Connecting to ' + callName + ' via Aircall… (Demo)');
    setLive(true); setSecs(0); setMuted(false);
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(() => setSecs((s) => s + 1), 1000);
  };
  const endCall = () => { if (timer.current) window.clearInterval(timer.current); setLive(false); actions.toast('Call ended. Log the outcome below and save to Notes.'); };
  const saveCall = () => {
    if (!callOutcome) { actions.toast('Select an outcome first', true); return; }
    actions.addAircallNote({ id: 0, type: 'aircall', comm_type: 'call', contact_name: callName, summary: composeAircallSummary('call', callName, callSummary || callOutcome), outcome: callOutcome, next_step: callNext, follow_up_date: callFollow || null, created_at: new Date().toISOString(), user_name: 'Sarah M.' }, '📞');
    setCallOutcome(''); setCallNext(''); setCallFollow(''); setCallSummary('');
  };
  const timerStr = `${Math.floor(secs / 60)}:${(secs % 60).toString().padStart(2, '0')}`;

  // Text state
  const [textContact, setTextContact] = useState('');
  const [textPhone, setTextPhone] = useState('');
  const [textBody, setTextBody] = useState('');
  const sendText = () => {
    if (!textPhone) { actions.toast('Enter a phone number first', true); return; }
    if (!textBody.trim()) { actions.toast('Message is required', true); return; }
    const name = textContact ? textContact.split('|')[0] : 'Contact';
    actions.addAircallNote({ id: 0, type: 'aircall', comm_type: 'text', contact_name: name, summary: composeAircallSummary('text', name, 'Text sent: ' + textBody.substring(0, 120) + (textBody.length > 120 ? '…' : '')), outcome: 'Sent', created_at: new Date().toISOString(), user_name: 'Sarah M.' }, '💬');
    setTextBody('');
  };

  // Email state
  const [emailContact, setEmailContact] = useState('');
  const [emailAddr, setEmailAddr] = useState('');
  const [emailCc, setEmailCc] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const sendEmail = () => {
    if (!emailAddr.trim()) { actions.toast('Enter recipient email', true); return; }
    if (!emailSubject.trim()) { actions.toast('Subject required', true); return; }
    if (!emailBody.trim()) { actions.toast('Body required', true); return; }
    const name = emailContact ? emailContact.split('|')[0] : 'Contact';
    actions.addAircallNote({ id: 0, type: 'aircall', comm_type: 'email', contact_name: name, summary: composeAircallSummary('email', name, 'Email sent — Subject: ' + emailSubject), outcome: 'Sent', created_at: new Date().toISOString(), user_name: 'Sarah M.' }, '✉️');
    setEmailAddr(''); setEmailCc(''); setEmailSubject(''); setEmailBody('');
  };

  return (
    <>
      <div className="mb-[18px] flex flex-wrap items-start justify-between gap-2.5">
        <div className="text-[11px] text-[#6b7fa3]">Reach leads and referral partners directly from CommunityLink. All interactions auto-logged.</div>
        <div className="flex flex-wrap gap-2">
          <span className="rounded-full border border-[#4fc87a]/25 bg-[#4fc87a]/10 px-3 py-1 text-[11px] font-extrabold text-[#4fc87a]">🚀 Max Exclusive</span>
          <span className="rounded-full border border-[#4fc87a]/20 bg-[#4fc87a]/[0.08] px-3 py-1 text-[11px] font-extrabold text-[#4fc87a]">● Connected (Demo)</span>
        </div>
      </div>
      <div className="mb-4 rounded-[9px] border border-[#3d9ee8]/15 bg-[#3d9ee8]/[0.06] px-3.5 py-2.5 text-[12px] text-[#3d9ee8]">👁 <strong>Demo Mode:</strong> No actual messages are sent. All actions simulate live Aircall behavior.</div>
      <div className="mb-[18px] flex flex-wrap gap-2">
        <button type="button" className={cn(CH_BTN, ch === 'call' && CH_ON)} onClick={() => setCh('call')}>📞 Call</button>
        <button type="button" className={cn(CH_BTN, ch === 'text' && CH_ON)} onClick={() => setCh('text')}>💬 Text</button>
        <button type="button" className={cn(CH_BTN, ch === 'email' && CH_ON)} onClick={() => setCh('email')}>✉️ Email</button>
      </div>

      {ch === 'call' && (
        <>
          <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
            <Card title="📞 Make a Call">
              <div className="flex flex-col gap-2.5">
                <Field label="Contact"><select className={FI} value={callContact} onChange={(e) => { setCallContact(e.target.value); setCallPhone(e.target.value.split('|')[1] || ''); }}>
                  <option value="">— Select lead or referral partner —</option>
                  <optgroup label="Hot Leads"><option value="Dorothy Harrison|(214)555-0142">Dorothy Harrison · (214)555-0142</option><option value="Gloria Tran|(469)555-0391">Gloria Tran · (469)555-0391</option><option value="Edna Michaels|(214)555-0567">Edna Michaels · (214)555-0567</option></optgroup>
                  <optgroup label="Referral Partners"><option value="Dr. Amanda Chen|(214)555-0181">Dr. Amanda Chen</option><option value="Sarah Kim RN|(214)555-0182">Sarah Kim RN — Parkland</option></optgroup>
                </select></Field>
                <Field label="Phone"><input className={FI} placeholder="(214) 555-0000" value={callPhone} onChange={(e) => setCallPhone(e.target.value)} /></Field>
                <Field label="Purpose"><select className={FI}><option>Lead Follow-Up</option><option>Tour Confirmation</option><option>Move-In Coordination</option><option>Referral Partner Touch-Base</option></select></Field>
                <Field label="Pre-Call Notes"><textarea className={`${FI} min-h-[56px]`} rows={2} placeholder="Key points…" /></Field>
                <div className="flex gap-2"><DemoButton className="flex-1" onClick={startCall}>📞 Call via Aircall</DemoButton><DemoButton variant="x" sm onClick={() => actions.toast('Scheduled!')}>🗓 Schedule</DemoButton></div>
              </div>
            </Card>
            {live && (
              <Card>
                <div className="rounded-[12px] border border-[#4fc87a]/25 bg-[#4fc87a]/[0.06] p-4 text-center">
                  <div className="mb-1 text-[32px]">📞</div>
                  <div className="mb-0.5 text-[15px] font-black text-[#4fc87a]">{callName}</div>
                  <div className="mb-3 text-[13px] text-[#4b6278]">{timerStr}</div>
                  <div className="flex justify-center gap-2">
                    <DemoButton variant="x" sm onClick={() => { setMuted((m) => !m); actions.toast(muted ? 'Unmuted' : 'Muted'); }}>{muted ? '🔇 Unmute' : '🎙 Mute'}</DemoButton>
                    <DemoButton variant="x" sm onClick={() => actions.toast('Transferring…')}>↗ Transfer</DemoButton>
                    <DemoButton variant="r" sm onClick={endCall}>⬛ End</DemoButton>
                  </div>
                </div>
              </Card>
            )}
          </div>
          <Card title="📋 Post-Call Log">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Outcome"><select className={FI} value={callOutcome} onChange={(e) => setCallOutcome(e.target.value)}><option value="">Select…</option><option>Connected — tour scheduled</option><option>Connected — follow-up set</option><option>Left voicemail</option><option>No answer</option><option>Referral committed</option></select></Field>
              <Field label="Next Action"><input className={FI} placeholder="e.g. Send proposal…" value={callNext} onChange={(e) => setCallNext(e.target.value)} /></Field>
              <Field label="Follow-Up Date"><input className={FI} type="date" value={callFollow} onChange={(e) => setCallFollow(e.target.value)} /></Field>
              <Field label="Summary"><textarea className={`${FI} min-h-[56px]`} rows={2} placeholder="What was discussed…" value={callSummary} onChange={(e) => setCallSummary(e.target.value)} /></Field>
            </div>
            <DemoButton variant="g" className="mt-2.5" onClick={saveCall}>💾 Save Log + Queue Follow-Up</DemoButton>
          </Card>
        </>
      )}

      {ch === 'text' && (
        <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
          <Card title="💬 Send Text">
            <div className="flex flex-col gap-2.5">
              <Field label="To"><select className={FI} value={textContact} onChange={(e) => { setTextContact(e.target.value); setTextPhone(e.target.value.split('|')[1] || ''); }}><option value="">— Select —</option><option value="Dorothy Harrison|(214)555-0142">Dorothy Harrison</option><option value="Gloria Tran|(469)555-0391">Gloria Tran</option><option value="Dr. Amanda Chen|(214)555-0181">Dr. Amanda Chen</option></select></Field>
              <Field label="Phone"><input className={FI} placeholder="(214) 555-0000" value={textPhone} onChange={(e) => setTextPhone(e.target.value)} /></Field>
              <Field label="Template"><select className={FI} value="" onChange={(e) => e.target.value && setTextBody(e.target.value)}><option value="">— Insert —</option>{AC_TEXT_TPL.map((t) => <option key={t.l} value={t.v}>{t.l}</option>)}</select></Field>
              <Field label={`Message  ${textBody.length}/160`}><textarea className={`${FI} min-h-[110px]`} rows={5} placeholder="Type message…" value={textBody} onChange={(e) => setTextBody(e.target.value)} /></Field>
              <div className="flex gap-2"><DemoButton className="flex-1" onClick={sendText}>💬 Send (Demo)</DemoButton><DemoButton variant="x" sm onClick={() => actions.toast('Scheduled')}>🗓</DemoButton></div>
            </div>
          </Card>
          <Card>
            <div className="mb-3.5 rounded-[8px] border border-[#f59e0b]/15 bg-[#f59e0b]/[0.06] px-3 py-2 text-[12px] text-[#f59e0b]">⚠ Use first names only. No health or financial details.</div>
            <div className="mb-2.5 text-[13px] font-extrabold text-[#f4f8ff]">📊 7-Day Text Stats</div>
            {[['Texts Sent', '18', '#f4f8ff'], ['Response Rate', '61%', '#4fc87a'], ['Tours Booked via Text', '3', '#f59e0b']].map(([k, v, c], i) => (
              <div key={i} className="flex justify-between border-b border-white/[0.05] py-2 last:border-0"><span className="text-[12px] text-[#8ba4c4]">{k}</span><span className="font-extrabold" style={{ color: c }}>{v}</span></div>
            ))}
            <div className="mt-3.5">
              <div className="mb-2 text-[10px] font-extrabold uppercase text-[#1e3a5f]">Last Thread — Dorothy</div>
              <div className="mb-1.5 ml-auto max-w-[82%] rounded-[10px_10px_3px_10px] border border-[#f59e0b]/20 bg-[#f59e0b]/10 px-3 py-2 text-[12px] text-[#f4f8ff]">Hi Dorothy! Confirming your tour Friday at 10am — still good?</div>
              <div className="max-w-[82%] rounded-[10px_10px_10px_3px] border border-white/[0.08] bg-[#071120] px-3 py-2 text-[12px] text-[#c8d6e8]">Yes! James will be joining me. Looking forward to it!</div>
            </div>
          </Card>
        </div>
      )}

      {ch === 'email' && (
        <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
          <Card title="✉️ Compose Email">
            <div className="flex flex-col gap-2.5">
              <Field label="To"><select className={FI} value={emailContact} onChange={(e) => { setEmailContact(e.target.value); setEmailAddr(e.target.value.split('|')[1] || ''); }}><option value="">— Select —</option><option value="Dorothy Harrison|jharrison.poa@email.com">Dorothy Harrison (POA)</option><option value="Gloria Tran|gtran.family@email.com">Gloria Tran (Family)</option><option value="Dr. Amanda Chen|a.chen@dallasmedical.com">Dr. Amanda Chen</option><option value="Sarah Kim RN|s.kim@parkland.org">Sarah Kim RN</option></select></Field>
              <Field label="Email"><input className={FI} type="email" placeholder="contact@email.com" value={emailAddr} onChange={(e) => setEmailAddr(e.target.value)} /></Field>
              <Field label="CC"><input className={FI} type="email" placeholder="optional" value={emailCc} onChange={(e) => setEmailCc(e.target.value)} /></Field>
              <Field label="Template"><select className={FI} value="" onChange={(e) => { const t = AC_EMAIL_TPL[e.target.value]; if (t) { setEmailSubject(t.s); setEmailBody(t.b); } }}><option value="">— Template —</option><option value="tour">Tour Confirmation</option><option value="proposal">Proposal / Rate Sheet</option><option value="thank">Thank You — Referral</option><option value="followup">General Follow-Up</option><option value="movein">Move-In Prep</option></select></Field>
              <Field label="Subject"><input className={FI} placeholder="Subject…" value={emailSubject} onChange={(e) => setEmailSubject(e.target.value)} /></Field>
              <Field label="Body"><textarea className={`${FI} min-h-[130px]`} rows={7} placeholder="Email body…" value={emailBody} onChange={(e) => setEmailBody(e.target.value)} /></Field>
              <div className="flex flex-wrap gap-2"><DemoButton className="flex-1" onClick={sendEmail}>✉️ Send (Demo)</DemoButton><DemoButton variant="x" sm onClick={() => actions.toast('Scheduled')}>🗓</DemoButton><DemoButton variant="x" sm onClick={() => actions.toast('Draft saved')}>📄</DemoButton></div>
            </div>
          </Card>
          <div>
            <Card title="📊 Email — 30 Days">
              {[['Emails Sent', '54', '#f4f8ff'], ['Open Rate', '68%', '#4fc87a'], ['Move-Ins Attributed', '4', '#f59e0b']].map(([k, v, c], i) => (
                <div key={i} className="flex justify-between border-b border-white/[0.05] py-2 last:border-0"><span className="text-[12px] text-[#8ba4c4]">{k}</span><span className="font-extrabold" style={{ color: c }}>{v}</span></div>
              ))}
            </Card>
            <Card title="📬 Recent">
              {[['Dorothy Harrison', 'Tour Confirmation · 1 day ago', 'Replied', '#4fc87a'], ['Dr. Amanda Chen', 'Thank You Referral · 3 days ago', 'Opened', '#f59e0b'], ['Walter Simmons', 'Follow-Up · 5 days ago', 'Sent', '#8ba4c4']].map(([n, s, st, c], i) => (
                <div key={i} className="border-b border-white/[0.04] py-2.5 last:border-0">
                  <div className="flex justify-between"><strong className="text-[12px] text-[#f4f8ff]">{n}</strong><span className="rounded-full px-2 py-0.5 text-[10px] font-bold" style={{ background: `${c}1a`, color: c }}>{st}</span></div>
                  <div className="text-[11px] text-[#4b6278]">{s}</div>
                </div>
              ))}
            </Card>
          </div>
        </div>
      )}

      <Card title="📋 Activity Log">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr>{['Type', 'Contact', 'Direction', 'Status', 'Team Member', 'Time', 'Outcome'].map((h) => <th key={h} className="border-b border-white/[0.05] px-2.5 py-2 text-left text-[10px] font-extrabold uppercase tracking-[0.06em] text-[#1e3a5f]">{h}</th>)}</tr>
            </thead>
            <tbody>
              {[
                ['📞 Call', 'blue', 'Dorothy Harrison', '↗ Out', '5m 18s', 'Sarah M.', 'Today 10:22am', 'Tour confirmed', 'green'],
                ['💬 Text', 'amber', 'Gloria Tran', '↗ Out', 'Delivered', 'Sarah M.', 'Yesterday', 'Replied', 'green'],
                ['✉️ Email', 'neutral', 'Dr. Amanda Chen', '↗ Out', 'Opened', 'Sarah M.', '2 days ago', 'No reply', 'amber'],
                ['📞 Call', 'blue', 'Sarah Kim RN', '↙ In', '3m 47s', 'Admin', '3 days ago', '2 referrals', 'green'],
              ].map((r, i) => (
                <tr key={i} className="hover:bg-white/[0.02]">
                  <td className="border-b border-white/[0.04] px-2.5 py-2.5"><span className={cn('inline-block rounded-full px-2 py-0.5 text-[10px] font-bold', aircallToneCls(r[1]))}>{r[0]}</span></td>
                  <td className="border-b border-white/[0.04] px-2.5 py-2.5"><strong className="text-[#f4f8ff]">{r[2]}</strong></td>
                  <td className="border-b border-white/[0.04] px-2.5 py-2.5 text-[#c8d6e8]">{r[3]}</td>
                  <td className="border-b border-white/[0.04] px-2.5 py-2.5 text-[#c8d6e8]">{r[4]}</td>
                  <td className="border-b border-white/[0.04] px-2.5 py-2.5 text-[#c8d6e8]">{r[5]}</td>
                  <td className="border-b border-white/[0.04] px-2.5 py-2.5 text-[#c8d6e8]">{r[6]}</td>
                  <td className="border-b border-white/[0.04] px-2.5 py-2.5"><span className={cn('inline-block rounded-full px-2 py-0.5 text-[10px] font-bold', aircallToneCls(r[8]))}>{r[7]}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-2 text-right text-[11px] text-[#4b6278]">Demo — no real messages sent</div>
      </Card>
    </>
  );
}

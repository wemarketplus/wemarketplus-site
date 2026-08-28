import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useState } from 'react';
import { MessageSquare, Mail } from 'lucide-react';
import { Button, Card, CardContent, Input, Select, Textarea } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { LOOKUP_PAGE_SIZE } from '@/shared/hooks';
import { useListClLeadsQuery, useCreateClLeadNoteMutation } from '@/modules/cl-leads';
import {
  AIRCALL_EMAIL_TEMPLATES,
  AIRCALL_TEXT_TEMPLATES,
  type AircallChannel,
} from '../constants/aircallConstants';

const fill = (template: string, name: string) =>
  template.replace(/\{name\}|\[Name\]/g, name || 'there');

// Aircall — Call · Text · Email (Max tier). Real (non-telephony) compose flow:
// pick a lead, start from a template, and "Send & Log" writes the touchpoint to
// the lead's activity timeline via the existing cl/lead-notes endpoint. No live
// dialer / real carrier send (that needs Aircall API credentials, out of scope).
export function AircallPage() {
  // LOOKUP_PAGE_SIZE, not a hand-picked number: ClListQueryDto caps `limit` at
  // MAX_LIMIT (100) and answers 400 above it, so `limit: 200` returned nothing at
  // all rather than a bigger page. `leadOptions` was permanently `[]`, the lead
  // picker had "Select a lead…" as its only entry, and since `canSend` requires a
  // leadId the "Send & log" button could never enable — for Text or for Email.
  // Same failure, same fix as ClOperationsPage and ReferralPortalPage.
  const { data: leadsData } = useListClLeadsQuery({ page: 1, limit: LOOKUP_PAGE_SIZE });
  const leadOptions = useMemo(
    () =>
      (leadsData?.data ?? []).map((l) => ({
        value: l.id,
        label: `${l.firstName} ${l.lastName ?? ''}`.trim(),
      })),
    [leadsData],
  );
  const [createNote, { isLoading: isSaving, error: saveError }] = useCreateClLeadNoteMutation();

  const [channel, setChannel] = useState<AircallChannel>('text');
  const [leadId, setLeadId] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [sent, setSent] = useState(false);

  const leadName = leadOptions.find((o) => o.value === leadId)?.label ?? '';

  const applyText = (tplBody: string) => setBody(fill(tplBody, leadName));
  const applyEmail = (key: string) => {
    const t = AIRCALL_EMAIL_TEMPLATES.find((e) => e.key === key);
    if (!t) return;
    setSubject(t.subject);
    setBody(fill(t.body, leadName));
  };

  const canSend = Boolean(leadId && body.trim()) && !isSaving;

  const send = async () => {
    if (!canSend) return;
    const channelLabel = channel === 'text' ? 'Text' : 'Email';
    const summary =
      channel === 'email' && subject.trim()
        ? `[${channelLabel}] ${subject.trim()} — ${body.trim()}`
        : `[${channelLabel}] ${body.trim()}`;
    await createNote({ leadId, summary, contactType: channelLabel }).unwrap();
    setSent(true);
    setBody('');
    setSubject('');
    setTimeout(() => setSent(false), 2500);
  };

  const channelBtn = (value: AircallChannel, label: string, Icon: typeof MessageSquare) => (
    <button
      type="button"
      onClick={() => setChannel(value)}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-pill border px-3.5 py-1.5 text-[12px] font-semibold transition-colors',
        channel === value
          ? 'border-primary/40 bg-primary/15 text-primary'
          : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
      )}
    >
      <Icon className="h-3.5 w-3.5" /> {label}
    </button>
  );

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Aircall — Call · Text · Email</h1>
        <p className="text-sm text-muted">
          Compose a text or email from a template and log it to the lead&apos;s activity timeline.
        </p>
      </header>

      <Card>
        <CardContent className="space-y-4 pt-6">
          <div className="flex gap-2">
            {channelBtn('text', 'Text', MessageSquare)}
            {channelBtn('email', 'Email', Mail)}
          </div>

          {saveError && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(saveError, 'Failed to log the message')}
            </p>
          )}

          <Select value={leadId} onChange={(e) => setLeadId(e.target.value)} aria-label="Lead">
            <option value="">Select a lead…</option>
            {leadOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>

          <div className="flex flex-wrap gap-2">
            {channel === 'text'
              ? AIRCALL_TEXT_TEMPLATES.map((t) => (
                  <Button key={t.label} variant="ghost" size="sm" onClick={() => applyText(t.body)}>
                    {t.label}
                  </Button>
                ))
              : AIRCALL_EMAIL_TEMPLATES.map((t) => (
                  <Button key={t.key} variant="ghost" size="sm" onClick={() => applyEmail(t.key)}>
                    {t.label}
                  </Button>
                ))}
          </div>

          {channel === 'email' && (
            <Input
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="Subject"
              aria-label="Email subject"
            />
          )}

          {/* <Textarea>, so the body lines up with the Subject <Input> directly
              above it — this was `px-3` on `bg-surface` against the shared
              `px-3.5` on `bg-surface-raised`. */}
          <Textarea
            rows={channel === 'email' ? 6 : 3}
            placeholder={channel === 'text' ? 'Type a text message…' : 'Type an email…'}
            value={body}
            onChange={(e) => setBody(e.target.value)}
          />

          <div className="flex items-center gap-3">
            <Button onClick={send} disabled={!canSend}>
              {sent ? 'Logged ✓' : `Send & log ${channel === 'text' ? 'text' : 'email'}`}
            </Button>
            <span className="text-[11px] text-muted-soft">
              Logs to the lead&apos;s activity timeline. No message is sent to a live carrier in this build.
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

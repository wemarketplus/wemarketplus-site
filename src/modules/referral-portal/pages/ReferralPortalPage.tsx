import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useState } from 'react';
import { toast } from 'sonner';
import { Copy, Plus, QrCode } from 'lucide-react';
import { Button, Card, CardContent, Input, Label, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { useListReferralsQuery } from '@/modules/referrals';
import { LOOKUP_PAGE_SIZE } from '@/shared/hooks/useRecordLookups';
import {
  useCreatePortalLinkMutation,
  useGetPortalLinkQrQuery,
  useListPortalLinksQuery,
  useUpdatePortalLinkMutation,
} from '../api/referralPortalApi';

/** The public form's origin — this app's own, which the API cannot know. */
const origin = () => window.location.origin;

function QrPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading } = useGetPortalLinkQrQuery({ id, origin: origin() });

  return (
    <Modal open onClose={onClose} title="Facility referral link" size="sm">
      {isLoading || !data ? (
        <p className="py-6 text-sm text-muted">Generating…</p>
      ) : (
        <div className="space-y-4 text-center">
          {/* Rendered server-side by the same `qrcode` package MFA enrolment
              uses, so no QR library is added to this bundle for one screen. */}
          <img
            src={data.qrDataUrl}
            alt="QR code for the facility referral form"
            className="mx-auto h-56 w-56 rounded-md bg-white p-2"
          />
          <p className="break-all text-[11px] text-muted">{data.url}</p>
          <Button
            variant="ghost"
            onClick={() => {
              void navigator.clipboard.writeText(data.url);
              toast.success('Link copied');
            }}
          >
            <Copy className="h-4 w-4" /> Copy link
          </Button>
          <p className="text-[11px] text-muted-soft">
            Print this for the facility, or send them the link. Anyone holding it
            can submit a referral, so revoke it if it is ever shared too widely.
          </p>
        </div>
      )}
    </Modal>
  );
}

/**
 * Issue, print and revoke the per-facility referral links.
 *
 * The revoke action is deliberately prominent and the copy says why: this is the
 * one credential the product hands to people outside the tenant, and an admin
 * needs to be able to kill a link the moment a poster walks out of a building.
 */
export function ReferralPortalPage() {
  const { data: links, isLoading } = useListPortalLinksQuery();
  // LOOKUP_PAGE_SIZE, not a hand-picked number: the backend caps `limit` at 100
  // and answers 400 above it — so `limit: 200` did not return a bigger page, it
  // returned nothing, and the facility picker rendered permanently empty.
  const { data: accounts } = useListReferralsQuery({ limit: LOOKUP_PAGE_SIZE });
  const [createLink, { isLoading: isCreating }] = useCreatePortalLinkMutation();
  const [updateLink] = useUpdatePortalLinkMutation();

  const [showCreate, setShowCreate] = useState(false);
  const [qrId, setQrId] = useState<string | null>(null);
  const [form, setForm] = useState({ referralSourceId: '', label: '' });

  const accountName = (id: string) =>
    accounts?.data.find((a) => a.id === id)?.name ?? 'Unknown facility';

  const submit = async () => {
    if (!form.referralSourceId) {
      toast.error('Choose a facility.');
      return;
    }
    try {
      const created = await createLink({
        referralSourceId: form.referralSourceId,
        label: form.label.trim() || undefined,
      }).unwrap();
      setShowCreate(false);
      setForm({ referralSourceId: '', label: '' });
      // Straight to the QR: issuing a link nobody can see is not a finished job.
      setQrId(created.id);
    } catch {
      toast.error('Could not create the link. Please try again.');
    }
  };

  const revoke = async (id: string, isActive: boolean) => {
    try {
      await updateLink({ id, patch: { isActive: !isActive } }).unwrap();
      toast.success(isActive ? 'Link revoked' : 'Link re-enabled');
    } catch {
      toast.error('Could not update the link.');
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>
            Facility referral portal
          </h1>
          <p className="text-sm text-muted">
            Give a facility a link or QR code so their staff can send referrals
            without an account.
          </p>
        </div>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4" /> New link
        </Button>
      </header>

      <Card>
        <CardContent className="px-0 py-0">
          {isLoading ? (
            <p className="px-6 py-6 text-sm text-muted">Loading links…</p>
          ) : !links || links.length === 0 ? (
            <p className="px-6 py-6 text-sm text-muted-soft">
              No referral links yet.
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {links.map((link) => (
                <li
                  key={link.id}
                  className="flex flex-wrap items-center gap-3 px-6 py-4"
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-foreground">
                      {accountName(link.referralSourceId)}
                    </p>
                    <p className="text-[11px] text-muted-soft">
                      {link.label ?? 'No label'} ·{' '}
                      {link.submissionCount} referral
                      {link.submissionCount === 1 ? '' : 's'}
                      {link.lastSubmissionAt &&
                        ` · last ${formatDate(link.lastSubmissionAt)}`}
                    </p>
                  </div>
                  <Pill tone={link.isActive ? 'g' : 'r'}>
                    {link.isActive ? 'Active' : 'Revoked'}
                  </Pill>
                  <Button variant="ghost" onClick={() => setQrId(link.id)}>
                    <QrCode className="h-4 w-4" /> QR
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => revoke(link.id, link.isActive)}
                  >
                    {link.isActive ? 'Revoke' : 'Re-enable'}
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title="New facility referral link"
        footer={
          <>
            <Button variant="ghost" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button onClick={submit} disabled={isCreating}>
              {isCreating ? 'Creating…' : 'Create link'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <Label htmlFor="pl-account">Facility</Label>
            <Select
              id="pl-account"
              value={form.referralSourceId}
              onChange={(e) =>
                setForm((f) => ({ ...f, referralSourceId: e.target.value }))
              }
            >
              <option value="">Choose a facility…</option>
              {accounts?.data.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="pl-label">Label</Label>
            <Input
              id="pl-label"
              value={form.label}
              onChange={(e) =>
                setForm((f) => ({ ...f, label: e.target.value }))
              }
              placeholder="ICU nurse station poster"
            />
            <p className="mt-1 text-[11px] text-muted-soft">
              Naming where the link is posted makes it obvious which one to
              revoke later.
            </p>
          </div>
        </div>
      </Modal>

      {qrId && <QrPanel id={qrId} onClose={() => setQrId(null)} />}
    </div>
  );
}

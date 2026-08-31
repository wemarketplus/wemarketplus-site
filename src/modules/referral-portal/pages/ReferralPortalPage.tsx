import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Copy, Plus, QrCode } from 'lucide-react';
import { Button, Input, Label, ListboxSelect } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { useListReferralsQuery } from '@/modules/referrals';
import { LOOKUP_PAGE_SIZE } from '@/shared/hooks/useRecordLookups';
import type { PortalLink } from '../types/referralPortalTypes';
import {
  useCreatePortalLinkMutation,
  useGetPortalLinkQrQuery,
  useListPortalLinksQuery,
  useUpdatePortalLinkMutation,
} from '../api/referralPortalApi';

/** The public form's origin — this app's own, which the API cannot know. */
const origin = () => window.location.origin;

function QrPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading, isError } = useGetPortalLinkQrQuery({
    id,
    origin: origin(),
  });

  return (
    <Modal open onClose={onClose} title="Facility referral link" size="sm">
      {isLoading ? (
        <p className="py-6 text-sm text-muted">Generating…</p>
      ) : isError || !data ? (
        /*
          The server now refuses to render a QR for a revoked or expired link, so
          this branch is reachable and must say what happened rather than sit on
          "Generating…" forever. It is also the belt to the row's braces: the QR
          button is hidden on a revoked row, but a panel already open when the
          revoke lands re-fetches and arrives here.
        */
        <p className="py-6 text-sm text-muted">
          This link is no longer active, so its QR code can’t be shown. Issue a
          new link for the facility instead.
        </p>
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
            can submit a referral, so revoke it if it is ever shared too widely —
            revoking kills this URL and QR code permanently.
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
      // The copy says what the server actually did. Revoking ROTATES the token
      // (see ReferralPortalService.updateLink), so the printed QR is dead for
      // good and re-enabling issues a different link — an admin who is not told
      // that will hand a facility a poster that no longer resolves.
      toast.success(
        isActive
          ? 'Link revoked. Its QR code and URL no longer work.'
          : 'Link re-enabled with a new URL — print the new QR code.',
      );
    } catch {
      toast.error('Could not update the link.');
    }
  };

  const facilityOptions = useMemo(
    () =>
      (accounts?.data ?? []).map((a) => ({ value: a.id, label: a.name })),
    [accounts],
  );

  /**
   * ── THE LISTING IS A TABLE NOW, WITH HEADINGS ────────────────────────────────
   *
   * Two reports, one cause. "Facility, Label and Action headings are missing"
   * and "Facility and Label are displayed in a single column" were both true and
   * both structural: this was a hand-rolled `<ul>` inside a Card, so there was no
   * `<thead>` to be missing a heading FROM, and the facility name, the label, the
   * submission count and the last-submission date all shared one `<div>` — two
   * stacked lines of text, not four cells. No CSS split can fix a list that has
   * no columns, so the list became a `<DataTable>`: the app's one table
   * primitive, already used by 55 pages, which renders the `<thead>`/`<th>` row,
   * inherits each header's alignment from its cells, supplies the empty state the
   * old markup hand-rolled, and wraps the body in `overflow-x-auto` so six
   * columns stay usable on a phone instead of squashing.
   *
   * One cell, one fact — that is the whole point of the fix, so nothing is
   * stacked back up inside a column:
   *
   *   Facility  the account name only
   *   Label     the label only ("—" when unset, not the old "No label" prose)
   *   Issued    createdAt. NEW, and load-bearing rather than decorative: the
   *             backend places no cap on active links per facility, and this
   *             tenant already has four live links for one hospital, two of them
   *             labelled identically "OPD". With facility + label the only things
   *             on screen, those two rows were pixel-identical — so "revoke the
   *             link" hit a coin-flip, the untouched twin kept working, and that
   *             is what "the revoked QR still works" looked like from the
   *             outside. A date makes the rows tellable apart.
   *   Referrals the count, and the last-submission date when there is one
   *   Status    the Active/Revoked pill
   *   Action    QR + Revoke/Re-enable, and nothing else
   */
  const columns: ReadonlyArray<Column<PortalLink>> = [
    {
      key: 'facility',
      header: 'Facility',
      cell: (link) => (
        <span className="text-sm font-semibold text-foreground">
          {accountName(link.referralSourceId)}
        </span>
      ),
    },
    {
      key: 'label',
      header: 'Label',
      cell: (link) => link.label ?? '—',
    },
    {
      key: 'issued',
      header: 'Issued',
      cell: (link) => formatDate(link.createdAt),
    },
    {
      key: 'submissions',
      header: 'Referrals',
      cell: (link) => (
        <span className="text-[13px]">
          {link.submissionCount}
          {link.lastSubmissionAt && (
            <span className="text-muted-soft">
              {' '}
              · last {formatDate(link.lastSubmissionAt)}
            </span>
          )}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (link) => (
        <Pill tone={link.isActive ? 'g' : 'r'}>
          {link.isActive ? 'Active' : 'Revoked'}
        </Pill>
      ),
    },
    {
      key: 'actions',
      header: 'Action',
      className: 'text-right',
      cell: (link) => (
        <div className="flex items-center justify-end gap-1">
          {/*
            NO QR BUTTON ON A REVOKED ROW.
            The row could display the red "Revoked" pill and still open a modal
            holding the live URL, the print-ready QR image and a working "Copy
            link" — offering an admin a credential the server has already
            refused. The server-side gate in ReferralPortalService.getLinkQr is
            what actually closes it (this button is only the door); hiding the
            door as well means the UI stops claiming the link is printable.
          */}
          {link.isActive && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setQrId(link.id)}
              aria-label={`QR code for ${accountName(link.referralSourceId)}`}
            >
              <QrCode className="h-4 w-4" /> QR
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            // Revoke reads destructive — it kills a credential a facility is
            // holding — while Re-enable is an ordinary quiet action.
            className={
              link.isActive
                ? 'text-destructive hover:bg-destructive/[0.08] hover:text-destructive'
                : undefined
            }
            title={
              link.isActive
                ? 'Revoke this link. Its QR code and URL stop working immediately and cannot be restored.'
                : 'Issue a fresh URL for this facility. The previously printed QR code will not work.'
            }
            onClick={() => revoke(link.id, link.isActive)}
          >
            {link.isActive ? 'Revoke' : 'Re-enable'}
          </Button>
        </div>
      ),
    },
  ];

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

      {isLoading ? (
        <p className="px-6 py-6 text-sm text-muted">Loading links…</p>
      ) : (
        <DataTable
          columns={columns}
          rows={links ?? []}
          rowKey={(link) => link.id}
          empty="No referral links yet."
        />
      )}

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
            {/*
              A <ListboxSelect>, not a native <Select>: this list is the tenant's
              whole account book (LOOKUP_PAGE_SIZE = 100 facilities), and a native
              select hands that count straight to the browser, which draws a popup
              as tall as the option list implies and places it over whatever is
              above the field. No CSS reaches that popup — `size`, `max-height`
              and `overflow` all apply to the closed control only. That is the
              "dropdown height is excessive" report on this screen, and it is the
              exact case ListboxSelect exists for: the same CONTROL_BASE trigger,
              a panel capped at MAX_PANEL_HEIGHT with its own scrollbar. Same
              swap, same reason, as Inbound leads' Referring organisation field.
            */}
            <ListboxSelect
              id="pl-account"
              value={form.referralSourceId}
              onChange={(referralSourceId) =>
                setForm((f) => ({ ...f, referralSourceId }))
              }
              options={facilityOptions}
              placeholder="Choose a facility…"
            />
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

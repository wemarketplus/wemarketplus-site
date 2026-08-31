import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useState } from 'react';
import { Mail, MessageSquare, Phone, Plus } from 'lucide-react';
import { toast } from 'sonner';
import { Button, SearchInput } from '@/shared/ui/core';
import { Alert, DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { useDebounce } from '@/shared/hooks';
import {
  CONTACT_TYPE_LABELS,
  PREFERRED_METHOD_LABELS,
  ROLE_TITLE_LABELS,
  useCreateHospiceContactMutation,
  useListHospiceContactsQuery,
  useUpdateHospiceContactMutation,
  type HospiceContactRecord,
} from '../api/hospiceContactsApi';
import { HospiceContactFormModal } from '../components/HospiceContactFormModal';
import { useContactOutreach } from '../hooks/useContactOutreach';

/**
 * The hover tint every quiet row control in the app wears — the same string
 * EntityRowActions applies to its pencil (see its doc for why a row control gets
 * a hover surface rather than a permanent border). Named here so the three
 * outreach icons and the pencil beside them cannot drift apart again.
 */
const ROW_ACTION_TINT = 'text-muted hover:bg-primary/[0.08] hover:text-primary';

/**
 * The hospice contact record — the referring PERSON that Prospects and Jobs point at.
 *
 * This screen is decision item 1 of the module-flow document. The backend has been
 * complete the whole time (`hl_contacts`, full CRUD at `/hl/contacts`) with no screen
 * and no nav entry, so the record every conversion creates was unbrowsable and
 * uneditable — while the visible "Contacts" nav item showed the unrelated Grants-side
 * table. Those two tables stay separate: merging them is explicitly ruled out, and
 * the field sets are disjoint.
 *
 * Each row carries click-to-call / text / email, and every one of those logs the
 * interaction automatically as a typed activity — see useContactOutreach.
 */
export function HospiceContactsPage() {
  const [search, setSearch] = useState('');
  const debounced = useDebounce(search, 300);
  const [editing, setEditing] = useState<HospiceContactRecord | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  const { data, isLoading, isError } = useListHospiceContactsQuery({
    limit: 50,
    search: debounced || undefined,
  });
  const [create, { isLoading: isSavingNew }] = useCreateHospiceContactMutation();
  const [update, { isLoading: isSavingEdit }] =
    useUpdateHospiceContactMutation();
  const { reach, pendingKey } = useContactOutreach();

  const contacts = data?.data ?? [];

  const columns: ReadonlyArray<Column<HospiceContactRecord>> = [
    {
      key: 'fullName',
      header: 'Contact',
      cell: (row) => (
        <span className="font-bold text-foreground">
          {row.fullName || `${row.firstName} ${row.lastName}`.trim()}
        </span>
      ),
    },
    {
      key: 'contactType',
      header: 'Type',
      cell: (row) => CONTACT_TYPE_LABELS[row.contactType] ?? row.contactType,
    },
    /*
      Role and Specialty are PROFILE, and they carry their own headers rather
      than riding as an unlabelled caption under the name. Stacked in the
      Contact cell they had no heading naming them, so on the list they read as
      part of the neighbouring reach block — the "profile fields showing under
      Reach" report. Reach below stays what its header says: how you contact the
      person. Nothing is dropped; both values simply sit under their own name.
    */
    {
      key: 'roleTitle',
      header: 'Role',
      cell: (row) => (row.roleTitle ? ROLE_TITLE_LABELS[row.roleTitle] : '—'),
    },
    {
      key: 'specialty',
      header: 'Specialty',
      cell: (row) => row.specialty || '—',
    },
    {
      key: 'reach',
      header: 'Reach',
      cell: (row) => (
        <div className="flex flex-col gap-0.5 text-[12px]">
          <span>{row.mobile ?? row.phone ?? '—'}</span>
          <span className="text-muted-soft">{row.email ?? '—'}</span>
        </div>
      ),
    },
    {
      key: 'preferredMethod',
      header: 'Prefers',
      cell: (row) =>
        row.preferredMethod
          ? PREFERRED_METHOD_LABELS[row.preferredMethod]
          : '—',
    },
    { key: 'npi', header: 'NPI', cell: (row) => row.npi ?? '—' },
    {
      key: 'doNotContact',
      header: 'Status',
      // Do-not-contact is a hard rule, not a hint: the server refuses a DNC contact
      // as an appointment attendee, and the outreach buttons refuse to dial.
      cell: (row) =>
        row.doNotContact ? (
          <Pill tone="r">Do not contact</Pill>
        ) : (
          <Pill tone="g">Contactable</Pill>
        ),
    },
    {
      key: 'actions',
      header: 'Actions',
      className: 'text-right',
      /*
        ── ONE TREATMENT FOR ALL FOUR ROW ACTIONS ──────────────────────────────
        The report was "the Action button colour is not the colour the UI
        design defines". The column held three treatments at once: three
        `ghost size="sm"` icon buttons (transparent, `text-muted` #6a726e, 48px
        wide because `sm` is `h-9 px-4` — text padding around a 16px glyph) and
        one `secondary size="sm"` "Edit" (bordered pill, `bg-surface-raised`,
        `text-foreground`). Measured live: three 48x36 transparent controls with
        `border-width: 0`, then one 58x36 filled control with a 1px 50%-alpha
        border. Whichever of the two you consider correct, the column disagreed
        with itself.

        The design system already answers this — `EntityRowActions` is the app's
        row-control idiom, used by twenty-odd tables: `ghost` + `size="square"`
        (36x36, no text padding) + 18px glyph + an explicit tinted hover
        (`hover:bg-primary/[0.08] hover:text-primary`) so the control announces
        its hit area on approach instead of carrying a permanent border.

        So Edit is now that component rather than a fourth spelling of it, and
        the three outreach icons wear the same square geometry and the same hover
        tint. `ROW_ACTION_TINT` is the one place that hover lives for this cell;
        the pencil's copy of it comes from EntityRowActions itself.

        The earlier `secondary` was a real fix to a real defect (a bare ghost
        TEXT button has no hit area at all) — it just fixed it from the wrong
        end, by making the labelled control the odd one out. An icon-only square
        with a hover surface has the hit area AND matches its neighbours.
      */
      cell: (row) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            variant="ghost"
            size="square"
            className={ROW_ACTION_TINT}
            aria-label={`Call ${row.fullName}`}
            title="Call and log"
            disabled={row.doNotContact || pendingKey === `${row.id}:call`}
            onClick={() => void reach(row, 'call')}
          >
            <Phone className="h-[18px] w-[18px]" />
          </Button>
          <Button
            variant="ghost"
            size="square"
            className={ROW_ACTION_TINT}
            aria-label={`Text ${row.fullName}`}
            title="Text and log"
            disabled={row.doNotContact || pendingKey === `${row.id}:text`}
            onClick={() => void reach(row, 'text')}
          >
            <MessageSquare className="h-[18px] w-[18px]" />
          </Button>
          <Button
            variant="ghost"
            size="square"
            className={ROW_ACTION_TINT}
            aria-label={`Email ${row.fullName}`}
            title="Email and log"
            disabled={row.doNotContact || pendingKey === `${row.id}:email`}
            onClick={() => void reach(row, 'email')}
          >
            <Mail className="h-[18px] w-[18px]" />
          </Button>
          <EntityRowActions
            onEdit={() => setEditing(row)}
            editLabel={`Edit ${row.fullName}`}
          />
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>
            Hospice contacts
          </h1>
          <p className="text-sm text-muted">
            The referring people your pipelines and jobs point at.{' '}
            {data?.total ?? 0} on file.
          </p>
        </div>
        {/*
          The leading <Plus> its four peers all carry — Leads' "Log referral",
          Referral sources' "Add source", Prospects' "Add prospect", Referral
          portal's "New link". The variant was already the shared `primary`
          default; the icon was the only way this page's header action differed
          from theirs.
        */}
        <Button onClick={() => setIsCreating(true)}>
          <Plus className="h-4 w-4" /> Add contact
        </Button>
      </header>

      {isError && (
        <Alert tone="r">
          <strong className="font-bold">Contacts unavailable.</strong> The
          /hl/contacts endpoint did not answer.
        </Alert>
      )}

      {/*
        <SearchInput>, not a bare <Input>. This was the one list screen in the app
        whose search box carried no magnifier and no clear button — the field was
        the right height and hairline, so it passed a geometry check while still
        reading as a plain text box next to the nineteen filter bars that mark
        their search with a glyph. The icon and its padding are a pair defined once
        in controlStyles.ts; hand-rolling the field is what loses them.
      */}
      <SearchInput
        wrapperClassName="max-w-md"
        value={search}
        onChange={setSearch}
        placeholder="Search by name, email, phone, NPI or specialty"
        aria-label="Search contacts"
      />

      {isLoading ? (
        <p className="text-sm text-muted">Loading contacts…</p>
      ) : (
        <DataTable columns={columns} rows={contacts} rowKey={(row) => row.id} />
      )}

      {isCreating && (
        <HospiceContactFormModal
          isSaving={isSavingNew}
          onClose={() => setIsCreating(false)}
          onSubmit={async (values) => {
            try {
              await create(values).unwrap();
              toast.success('Contact added.');
              setIsCreating(false);
            } catch {
              toast.error('Could not add that contact.');
            }
          }}
        />
      )}

      {editing && (
        <HospiceContactFormModal
          contact={editing}
          isSaving={isSavingEdit}
          onClose={() => setEditing(null)}
          onSubmit={async (values) => {
            try {
              await update({ id: editing.id, patch: values }).unwrap();
              toast.success('Contact updated.');
              setEditing(null);
            } catch {
              toast.error('Could not update that contact.');
            }
          }}
        />
      )}
    </div>
  );
}

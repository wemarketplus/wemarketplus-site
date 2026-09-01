import { useState } from 'react';
import { Button, Checkbox, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { SUBSECTION_TITLE } from '@/shared/ui/core/typography';
import { Modal } from '@/shared/ui/feedback';
import {
  CONTACT_TYPE_LABELS,
  PREFERRED_METHOD_LABELS,
  ROLE_TITLE_LABELS,
  type CreateHospiceContactRequest,
  type HospiceContactPreferredMethod,
  type HospiceContactRecord,
  type HospiceContactRoleTitle,
  type HospiceContactType,
} from '../api/hospiceContactsApi';

interface Props {
  /** Omit to create; supply to edit. */
  contact?: HospiceContactRecord;
  isSaving: boolean;
  onClose: () => void;
  onSubmit: (values: CreateHospiceContactRequest) => Promise<void>;
}

/**
 * Create / edit form for the hospice contact record.
 *
 * `companyId` is deliberately NOT editable here. The account link is set by lead
 * conversion (or from the Referral source screen), and letting a contact be re-homed
 * from this form would silently move relationship history between accounts. Same
 * reasoning as notes: the two note targets are queryable but not updatable.
 */
export function HospiceContactFormModal({
  contact,
  isSaving,
  onClose,
  onSubmit,
}: Props) {
  const [firstName, setFirstName] = useState(contact?.firstName ?? '');
  const [lastName, setLastName] = useState(contact?.lastName ?? '');
  const [contactType, setContactType] = useState<HospiceContactType>(
    contact?.contactType ?? 'referral_source',
  );
  const [roleTitle, setRoleTitle] = useState<HospiceContactRoleTitle | ''>(
    contact?.roleTitle ?? '',
  );
  const [phone, setPhone] = useState(contact?.phone ?? '');
  const [mobile, setMobile] = useState(contact?.mobile ?? '');
  const [email, setEmail] = useState(contact?.email ?? '');
  const [fax, setFax] = useState(contact?.fax ?? '');
  const [preferredMethod, setPreferredMethod] = useState<
    HospiceContactPreferredMethod | ''
  >(contact?.preferredMethod ?? '');
  const [npi, setNpi] = useState(contact?.npi ?? '');
  const [specialty, setSpecialty] = useState(contact?.specialty ?? '');
  const [doNotContact, setDoNotContact] = useState(
    contact?.doNotContact ?? false,
  );
  const [notes, setNotes] = useState(contact?.notes ?? '');
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!firstName.trim() || !lastName.trim()) {
      setError('First and last name are both required.');
      return;
    }
    setError(null);
    /**
     * Blank string fields are OMITTED; the two blank ENUM fields are sent as NULL.
     * The difference is the whole fix for "clearing a role or preferred method
     * silently fails to save".
     *
     * The API reads an omitted key as "leave it alone" and an explicit null as
     * "clear it". For a text field, omitting a blank is right — an empty string
     * would fail the @IsEmail / @MaxLength validators on a field the user simply
     * left alone. But for `roleTitle` and `preferredMethod`, omitting is the ONLY
     * thing this builder used to do, so picking the blank option to clear a value
     * set earlier sent nothing at all and the old value stayed put.
     *
     * They cannot be sent as `''` instead: both are Postgres enum columns, so an
     * empty string is not a member and @IsEnum would reject it. `null` is the only
     * way to express "no value" for these two.
     *
     * Harmless on create, where there is nothing to clear — null and omitted both
     * write null into a nullable column — so the two paths stay one builder rather
     * than diverging on a distinction only one of them cares about.
     */
    const values: CreateHospiceContactRequest = {
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      contactType,
      doNotContact,
      roleTitle: roleTitle || null,
      preferredMethod: preferredMethod || null,
      ...(phone.trim() ? { phone: phone.trim() } : {}),
      ...(mobile.trim() ? { mobile: mobile.trim() } : {}),
      ...(email.trim() ? { email: email.trim() } : {}),
      ...(fax.trim() ? { fax: fax.trim() } : {}),
      ...(npi.trim() ? { npi: npi.trim() } : {}),
      ...(specialty.trim() ? { specialty: specialty.trim() } : {}),
      ...(notes.trim() ? { notes: notes.trim() } : {}),
    };
    await onSubmit(values);
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={contact ? `Edit ${contact.fullName}` : 'Add hospice contact'}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={isSaving}>
            {isSaving ? 'Saving…' : contact ? 'Save changes' : 'Add contact'}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/*
          ── WHY THIS FORM IS GROUPED ──────────────────────────────────────────
          The report was "the Reach tab shows Mobile, Email, First Name, Last
          Name, Role at Facility and Specialty — profile fields already captured
          elsewhere, duplicated into Reach".

          There is no tab, and there never was: this is one flat twelve-cell grid,
          and the Hospice contacts LIST has a "Reach" column beside Role and
          Specialty columns. Reading that header across a nine-column table is
          what produced the report — nothing was duplicated, and nothing is stored
          twice. Every one of the six named fields is a distinct, single column on
          `hl_contacts`, so deleting any of them would delete data, not a copy:
          `firstName`/`lastName` compose the server-side `fullName` the whole
          module keys off, and `roleTitle`/`specialty` are what Prospects and Jobs
          display. Removing them is not the fix.

          What WAS wrong is that "Reach" had no defined boundary, so any field
          near it read as being in it. So the boundary is drawn here, once, and
          the two groups say which is which:

            Profile — who the contact is:    firstName, lastName, contactType,
                                             roleTitle, npi, specialty
            Reach   — how to contact them:   phone, mobile, email, fax,
                                             preferredMethod, doNotContact

          Mobile and Email are the two of the six that genuinely belong to Reach,
          and they now sit under a heading that says so. The submitted payload is
          byte-identical — this is grouping, not a data-model change — which is
          why create and edit are untouched. Headings are `full`-width rows in the
          same two-column grid rather than nested <div>s, so every field keeps its
          existing column and 44px band.
        */}
        <h3 className={`${SUBSECTION_TITLE} sm:col-span-2`}>Profile</h3>
        <div>
          <Label htmlFor="hc-first">First name</Label>
          <Input
            id="hc-first"
            value={firstName}
            onChange={(e) => setFirstName(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="hc-last">Last name</Label>
          <Input
            id="hc-last"
            value={lastName}
            onChange={(e) => setLastName(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="hc-type">Contact type</Label>
          <Select
            id="hc-type"
            value={contactType}
            onChange={(e) =>
              setContactType(e.target.value as HospiceContactType)
            }
          >
            {(
              Object.keys(CONTACT_TYPE_LABELS) as HospiceContactType[]
            ).map((value) => (
              <option key={value} value={value}>
                {CONTACT_TYPE_LABELS[value]}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="hc-role">Role at facility</Label>
          <Select
            id="hc-role"
            value={roleTitle}
            onChange={(e) =>
              setRoleTitle(e.target.value as HospiceContactRoleTitle | '')
            }
          >
            {/*
              Placeholder for an optional field, not a value. It was labelled `—`,
              which reads in the open list as a seventh selectable role. Nothing
              behind it is a dash: hl_contacts_roletitle_enum holds exactly the six
              roles and is nullable, so "no role" is NULL. The empty VALUE is
              unchanged, so submit still omits `roleTitle`.
            */}
            <option value="">Select a role…</option>
            {(
              Object.keys(ROLE_TITLE_LABELS) as HospiceContactRoleTitle[]
            ).map((value) => (
              <option key={value} value={value}>
                {ROLE_TITLE_LABELS[value]}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="hc-npi">NPI</Label>
          <Input id="hc-npi" value={npi} onChange={(e) => setNpi(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="hc-specialty">Specialty</Label>
          <Input
            id="hc-specialty"
            value={specialty}
            onChange={(e) => setSpecialty(e.target.value)}
          />
        </div>
        <h3 className={`${SUBSECTION_TITLE} mt-2 sm:col-span-2`}>Reach</h3>
        <div>
          <Label htmlFor="hc-phone">Phone</Label>
          <Input
            id="hc-phone"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="hc-mobile">Mobile</Label>
          <Input
            id="hc-mobile"
            value={mobile}
            onChange={(e) => setMobile(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="hc-email">Email</Label>
          <Input
            id="hc-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="hc-fax">Fax</Label>
          <Input
            id="hc-fax"
            value={fax}
            onChange={(e) => setFax(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="hc-prefers">Preferred method</Label>
          <Select
            id="hc-prefers"
            value={preferredMethod}
            onChange={(e) =>
              setPreferredMethod(
                e.target.value as HospiceContactPreferredMethod | '',
              )
            }
          >
            {/* Same placeholder defect as Role at facility, same field group. */}
            <option value="">Select a method…</option>
            {(
              Object.keys(
                PREFERRED_METHOD_LABELS,
              ) as HospiceContactPreferredMethod[]
            ).map((value) => (
              <option key={value} value={value}>
                {PREFERRED_METHOD_LABELS[value]}
              </option>
            ))}
          </Select>
        </div>
        {/*
          A TWO-PART CELL, like every one of its eleven siblings: a <Label> row,
          then the control in the 44px band under it.

          The previous shape was the checkbox row AS the grid cell, held level with
          the input beside it by `self-end sm:h-11` (CONTROL_HEIGHT). That did get
          the box onto the neighbour's centre line — measured at 0px offset from the
          Specialty input's centre — and it is still not what "aligned" meant here.
          It was the only cell in the twelve-cell grid with no label row, so column
          two read LABEL/control five times and then a bare checkbox floating in
          ~24px of dead space, with the app's one lower-case 13px field caption
          sitting down in the control band where every other cell holds a 12px
          uppercase eyebrow. `self-end` also does nothing in the single-column
          layout below 640px, where the row loses its 44px band entirely and drifts
          up into the gap under Specialty — so the misalignment was real on mobile
          and cosmetic-but-visible on desktop.

          With the Label supplying the offset, `h-11` replaces `self-end sm:h-11`
          and holds at every width. `id`/`htmlFor` follow the `hc-*` convention the
          other eleven fields use: the wrapping <label> already toggled the box
          implicitly, but nothing else could point at it (`aria-describedby`, a test,
          an error message) and the form's own naming rule had one exception.
        */}
        <div>
          <Label htmlFor="hc-dnc">Contact preference</Label>
          {/*
            No `htmlFor` on this inner <label>: it WRAPS the box, which is the
            app's checkbox-row idiom (TasksFilters, CustomRoleFormModal,
            EditUserModal) and associates them implicitly. The `hc-dnc` id is
            there for the <Label> eyebrow above, so clicking that focuses the box
            exactly as clicking "SPECIALTY" focuses its input.
          */}
          <label className="flex h-11 cursor-pointer items-center gap-2 text-[13px] text-foreground">
            <Checkbox
              id="hc-dnc"
              checked={doNotContact}
              onChange={(e) => setDoNotContact(e.target.checked)}
            />
            Do not contact
          </label>
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="hc-notes">Notes</Label>
          <Textarea
            id="hc-notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
          />
        </div>
      </div>
      {error && <p className="mt-3 text-[12px] text-destructive">{error}</p>}
    </Modal>
  );
}

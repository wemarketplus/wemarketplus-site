import { useState } from 'react';
import { Button, Checkbox, Input, Label, Select, Textarea } from '@/shared/ui/core';
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
    // Empty strings are omitted rather than sent: the backend treats an omitted key
    // as "leave alone" and a null as "clear", and an empty string would fail the
    // @IsEmail / @MaxLength validators on fields the user simply left blank.
    const values: CreateHospiceContactRequest = {
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      contactType,
      doNotContact,
      ...(roleTitle ? { roleTitle } : {}),
      ...(phone.trim() ? { phone: phone.trim() } : {}),
      ...(mobile.trim() ? { mobile: mobile.trim() } : {}),
      ...(email.trim() ? { email: email.trim() } : {}),
      ...(fax.trim() ? { fax: fax.trim() } : {}),
      ...(preferredMethod ? { preferredMethod } : {}),
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
            <option value="">—</option>
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
            <option value="">—</option>
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
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-[13px] text-foreground">
            <Checkbox
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

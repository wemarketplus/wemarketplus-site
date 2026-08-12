import { useMemo } from 'react';
import { useGetPatientContextQuery } from '@/modules/prospects/api/prospectsApi';
import { HL_MARKETING_ROLES, useRole } from '@/shared/rbac';
import type { EntityField } from '@/shared/ui/entity';
import { NOTE_FIELDS } from '../constants/activityConstants';
import type { NoteFormValues } from '../schema/noteSchema';

/**
 * The note form's field list, and the read-only values that go with it.
 *
 * THE PROBLEM THIS SOLVES: `NOTE_FIELDS` is one static list, so every role got the
 * marketer's form — including the Referral source and Contact pickers. Those two
 * lists come from `GET /referral-sources` and `GET /hl/contacts`, both
 * `@Roles(...HL_MARKETING_ROLES)`, so a Nurse or Caregiver opened "Add note", clicked
 * Referral source, and found a dropdown holding nothing but "No referral source".
 * Not a loading state and not a permission error — a control that could never work.
 *
 * WHAT A CLINICIAN GETS INSTEAD: the same two rows, in the same place, rendered
 * read-only from the SELECTED PATIENT's own record — who referred them and the
 * contact on that referral. That is ordinary clinical context (it is in the chart),
 * while the lists themselves stay closed: `GET /prospects/:id/patient-context`
 * answers for one named patient and carries names only, so no clinician can
 * enumerate the tenant's accounts or see their economics.
 *
 * A clinical note targets the patient, never the facility, so read-only is the right
 * shape and not a degraded one — and any reference already on the record stays
 * registered, so a clinician editing a marketer's note cannot silently drop it.
 */
export function useNoteFormFields(
  open: boolean,
  prospectId: string | undefined,
): {
  fields: ReadonlyArray<EntityField<NoteFormValues>>;
  readOnlyValues: Record<string, string | null | undefined>;
} {
  const { isAny } = useRole();
  const isMarketing = isAny(HL_MARKETING_ROLES);

  // Only for the role that cannot use the pickers, only while the form is open, and
  // only once a patient is chosen — there is no context to fetch before that.
  const { data, isFetching } = useGetPatientContextQuery(prospectId as string, {
    skip: isMarketing || !open || !prospectId,
  });

  const fields = useMemo<ReadonlyArray<EntityField<NoteFormValues>>>(() => {
    if (isMarketing) return NOTE_FIELDS;
    return NOTE_FIELDS.map((field) => {
      if (field.name === 'referralSourceId') {
        return { ...field, type: 'readonly' as const, label: 'Referred by' };
      }
      if (field.name === 'contactId') {
        return { ...field, type: 'readonly' as const, label: 'Main contact' };
      }
      return field;
    });
  }, [isMarketing]);

  const readOnlyValues = useMemo<Record<string, string | null | undefined>>(() => {
    if (isMarketing) return {};
    // No patient chosen yet — so make no claim. "Not on file" (what `null` renders)
    // would be a statement about a patient nobody has named, and it is outright
    // wrong on a marketer's facility-scoped note opened for edit: that note HAS a
    // referral source, it just isn't a patient's.
    if (!prospectId) {
      return { referralSourceId: '—', contactId: '—' };
    }
    if (isFetching || !data) {
      return { referralSourceId: undefined, contactId: undefined };
    }
    const contact = data.primaryContactName
      ? // Same shape the contact picker uses elsewhere ("Name — role"), so the two
        // read as the same kind of thing across the app.
        [data.primaryContactName, data.primaryContactRole?.replace(/_/g, ' ')]
          .filter(Boolean)
          .join(' — ')
      : null;
    return {
      referralSourceId: data.referralSourceName,
      contactId: contact,
    };
  }, [isMarketing, prospectId, isFetching, data]);

  return { fields, readOnlyValues };
}

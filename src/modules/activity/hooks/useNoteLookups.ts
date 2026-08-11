import {
  hospiceContactLabel,
  useListHospiceContactsQuery,
} from '@/modules/hospice-contacts/api/hospiceContactsApi';
import { useGetMyPatientsQuery } from '@/modules/appointments/api/appointmentsApi';
import { useListProspectsQuery } from '@/modules/prospects/api/prospectsApi';
import { useListReferralsQuery } from '@/modules/referrals/api/referralsApi';
import { useRole, HL_MARKETING_ROLES } from '@/shared/rbac';
import { LOOKUP_PAGE_SIZE, useLookupOptions } from '@/shared/hooks';
import type { EntitySelectOption } from '@/shared/ui/entity';

const PAGE = { page: 1, limit: LOOKUP_PAGE_SIZE } as const;

/**
 * The patients a user may attach a note to, as picker options.
 *
 * TWO DIFFERENT PATIENT SOURCES, chosen by role. Marketing roles pick from the
 * whole pipeline (GET /prospects). Nurse and Caregiver get 403 there — a pipeline
 * row is PHI-bearing account data — so they pick from GET
 * /hl/appointments/my-patients, the patients their OWN calendar already names.
 * Without this split their picker came back empty from a failed request and the
 * form could not be submitted at all: a note requires a target
 * (NotesService.assertHasTarget plus a DB check constraint), so an empty picker is
 * not a cosmetic problem, it is a dead form.
 *
 * Exported separately from `useNoteLookups` because the Notes screen needs THIS
 * list on its own, to filter the team notes down to one patient. Reading it from
 * the full lookup bundle would drag the referral-source and contact lists along —
 * two requests the filter has no use for, on a tab a clinician opens constantly.
 * The role split lives here once so the picker and the filter can never disagree
 * about which patients a persona is allowed to name.
 */
export function useNotePatientOptions(
  enabled: boolean,
): readonly EntitySelectOption[] | undefined {
  const { isAny } = useRole();
  const isMarketing = isAny(HL_MARKETING_ROLES);
  // Skip the request this role is not allowed to make, rather than firing it and
  // reading a 403 as "no records".
  const prospects = useListProspectsQuery(PAGE, {
    skip: !enabled || !isMarketing,
  });
  const myPatients = useGetMyPatientsQuery(undefined, {
    skip: !enabled || isMarketing,
  });

  const pipelineOptions = useLookupOptions(
    prospects.data?.data,
    prospects.isLoading,
    (p) => p.pipelineName?.trim() || p.patientName,
  );
  const myPatientOptions = useLookupOptions(
    myPatients.data,
    myPatients.isLoading,
    (p) => p.patientName,
  );

  return isMarketing ? pipelineOptions : myPatientOptions;
}

/**
 * The three record pickers on the note form. A note targets a prospect, a referral
 * source or a contact — each of those used to be a free-text "paste the UUID" box,
 * which no end user could actually fill.
 *
 * `enabled` is the modal's open state, so the lists are only fetched while the form
 * is on screen rather than on every visit to the Notes tab.
 *
 * The referral-source and contact pickers stay marketing-only for the same reason
 * their endpoints are: a clinician logs against a patient, not against an account.
 */
export function useNoteLookups(
  enabled: boolean,
): Record<string, readonly EntitySelectOption[] | undefined> {
  const { isAny } = useRole();
  const skipPipeline = !enabled || !isAny(HL_MARKETING_ROLES);

  const referrals = useListReferralsQuery(PAGE, { skip: skipPipeline });
  const contacts = useListHospiceContactsQuery(PAGE, { skip: skipPipeline });

  return {
    prospectId: useNotePatientOptions(enabled),
    referralSourceId: useLookupOptions(
      referrals.data?.data,
      referrals.isLoading,
      (r) => r.name,
    ),
    contactId: useLookupOptions(
      contacts.data?.data,
      contacts.isLoading,
      hospiceContactLabel,
    ),
  };
}

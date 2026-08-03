import {
  hospiceContactLabel,
  useListHospiceContactsQuery,
} from '@/modules/hospice-contacts/api/hospiceContactsApi';
import { useListProspectsQuery } from '@/modules/prospects/api/prospectsApi';
import { useListReferralsQuery } from '@/modules/referrals/api/referralsApi';
import { LOOKUP_PAGE_SIZE, useLookupOptions } from '@/shared/hooks';
import type { EntitySelectOption } from '@/shared/ui/entity';

const PAGE = { page: 1, limit: LOOKUP_PAGE_SIZE } as const;

/**
 * The three record pickers on the note form. A note targets a prospect, a referral
 * source or a contact — each of those used to be a free-text "paste the UUID" box,
 * which no end user could actually fill.
 *
 * `enabled` is the modal's open state, so the three lists are only fetched while
 * the form is on screen rather than on every visit to the Notes tab.
 */
export function useNoteLookups(
  enabled: boolean,
): Record<string, readonly EntitySelectOption[] | undefined> {
  const skip = !enabled;

  const prospects = useListProspectsQuery(PAGE, { skip });
  const referrals = useListReferralsQuery(PAGE, { skip });
  const contacts = useListHospiceContactsQuery(PAGE, { skip });

  return {
    prospectId: useLookupOptions(
      prospects.data?.data,
      prospects.isLoading,
      (p) => p.pipelineName?.trim() || p.patientName,
    ),
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

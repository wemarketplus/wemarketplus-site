import {
  useApplicationLookup,
  useCompanyLookup,
  useFundingLookup,
} from '@/shared/hooks';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { CONTACT_RECORD_TYPE } from '../constants/contactsConstants';

/**
 * Options for the contact form's `recordId` picker — the second half of the
 * polymorphic (recordType, recordId) pair. Which list to offer is decided by the
 * record type the user chose, so this is a DEPENDENT lookup.
 *
 * All three lists are declared on every render because RTK Query hooks must be
 * called unconditionally and in a fixed order; the two that were not chosen are
 * `skip`ped, so exactly one request goes out (none until a type is picked).
 *
 * Returns `undefined` both while the chosen list is loading and when no type is
 * chosen yet — either way there is nothing to pick, and EntityFormModal keeps the
 * picker disabled (naming the record-type field in the latter case).
 *
 * DORMANT BRANCHES: the `funding` and `applications` lookups below are
 * Grants-domain and NOT NEEDED / PENDING REMOVAL. Since 2026-08-06 neither type
 * appears in CONTACT_RECORD_TYPE_OPTIONS, so `recordType` can never equal them
 * from the UI — both hooks stay permanently `skip`ped and no request goes out.
 * They are kept only so a contact already attached to one still resolves, and so
 * the picker can be restored in one edit. Remove with the Grants modules.
 */
export function useAttachableRecordLookup(
  recordType: string | undefined,
  enabled: boolean,
): readonly EntitySelectOption[] | undefined {
  const companies = useCompanyLookup(
    enabled && recordType === CONTACT_RECORD_TYPE.Company,
  );
  const funding = useFundingLookup(
    enabled && recordType === CONTACT_RECORD_TYPE.FundingOpportunity,
  );
  const applications = useApplicationLookup(
    enabled && recordType === CONTACT_RECORD_TYPE.Application,
  );

  switch (recordType) {
    case CONTACT_RECORD_TYPE.Company:
      return companies;
    case CONTACT_RECORD_TYPE.FundingOpportunity:
      return funding;
    case CONTACT_RECORD_TYPE.Application:
      return applications;
    default:
      return undefined;
  }
}

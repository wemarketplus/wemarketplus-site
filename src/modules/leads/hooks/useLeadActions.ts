import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { prospectsApi } from '@/modules/prospects/api/prospectsApi';
import {
  useConvertLeadMutation,
  useCreateLeadMutation,
  useDisqualifyLeadMutation,
} from '../api/leadsApi';
import type {
  LeadDisqualifyReason,
  LeadSourceType,
} from '../types/leadsTypes';
import type { NewLeadFormValues } from '../schema/leadSchema';
import { compactPayload } from '../utils/leadsUtils';

/**
 * Create / convert / disqualify. Conversion writes three records server-side
 * (Company + Contact + Pipeline), so on success the prospects cache is invalidated —
 * the new pipeline row must appear on the Prospects and Pipeline screens immediately.
 */
export function useLeadActions() {
  const dispatch = useAppDispatch();
  const [addOpen, setAddOpen] = useState(false);
  const [create, { isLoading: isCreating }] = useCreateLeadMutation();
  const [convert, { isLoading: isConverting }] = useConvertLeadMutation();
  const [disqualify, { isLoading: isDisqualifying }] =
    useDisqualifyLeadMutation();

  const submitNew = useCallback(
    async (values: NewLeadFormValues) => {
      try {
        await create(
          compactPayload({
            ...values,
            sourceType: values.sourceType as LeadSourceType,
          }),
        ).unwrap();
        toast.success('Lead captured.');
        setAddOpen(false);
        return true;
      } catch {
        toast.error('Could not save that lead.');
        return false;
      }
    },
    [create],
  );

  const convertLead = useCallback(
    async (id: string) => {
      try {
        const result = await convert({ id }).unwrap();
        // A conversion creates a prospects (pipeline) row.
        dispatch(
          prospectsApi.util.invalidateTags([
            { type: 'Prospects.List', id: 'PARTIAL-LIST' },
          ]),
        );
        toast.success(
          `Converted · pipeline created${
            result.companyId ? ' and linked to the account' : ''
          }.`,
        );
        return true;
      } catch {
        toast.error('Could not convert that lead.');
        return false;
      }
    },
    [convert, dispatch],
  );

  const disqualifyLead = useCallback(
    async (id: string, reason: LeadDisqualifyReason) => {
      try {
        await disqualify({ id, body: { disqualifyReason: reason } }).unwrap();
        toast.success('Lead disqualified.');
        return true;
      } catch {
        toast.error('Could not disqualify that lead.');
        return false;
      }
    },
    [disqualify],
  );

  return {
    addOpen,
    openAdd: () => setAddOpen(true),
    closeAdd: () => setAddOpen(false),
    isCreating,
    isConverting,
    isDisqualifying,
    submitNew,
    convertLead,
    disqualifyLead,
  };
}

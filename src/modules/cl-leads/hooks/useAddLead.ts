import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { addLead, closeAddLead } from '../store/leadsSlice';
import type { NewLeadFormValues } from '../schema/leadSchema';

export function useAddLead() {
  const dispatch = useAppDispatch();
  const open = useAppSelector((s) => s.clLeads.addModalOpen);

  const close = () => dispatch(closeAddLead());

  const submit = (v: NewLeadFormValues) => {
    dispatch(addLead(v));
    toast.success(`Added ${v.name} to the pipeline`);
  };

  return { open, close, submit };
}

import { toast } from 'sonner';

export function useBreachWorkflow() {
  const onInitiate = () => toast.error('Breach workflow — confirm + backend pending');
  return { onInitiate };
}

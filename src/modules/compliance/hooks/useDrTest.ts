import { toast } from 'sonner';

export function useDrTest() {
  const onRun = () => toast.message('DR test — backend endpoint pending');
  return { onRun };
}

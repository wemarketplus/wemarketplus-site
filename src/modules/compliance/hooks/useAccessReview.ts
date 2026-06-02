import { toast } from 'sonner';

export function useAccessReview() {
  const onRun = () => toast.message('Access review — backend endpoint pending');
  return { onRun };
}

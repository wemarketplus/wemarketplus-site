import { useState } from 'react';
import { toast } from 'sonner';
import { confirm } from '@/shared/ui/feedback';

// Same minimal RTK Query mutation trigger shape used by useEntityCrud.
type MutationTrigger<TArg, TResult> = (arg: TArg) => { unwrap: () => Promise<TResult> };

interface UseBulkDeleteArgs {
  // Human label for toasts / confirm copy, e.g. "contact".
  noun: string;
  // Plural form when it is not simply `${noun}s` (e.g. "companies").
  nounPlural?: string;
  remove: MutationTrigger<string, unknown>;
}

export interface BulkDeleteProgress {
  done: number;
  total: number;
}

export interface BulkDeleteController {
  isDeleting: boolean;
  progress: BulkDeleteProgress | null;
  // Confirms once, then deletes each id sequentially. Resolves with a
  // { succeeded, failed } summary and shows a summary toast. On success the
  // caller should clear its selection. Returns null if the user cancels.
  run: (ids: readonly string[]) => Promise<{ succeeded: number; failed: number } | null>;
}

// Orchestrates a bulk delete: single confirm, sequential per-id delete (so a
// blocked/403 row doesn't abort the rest), progress state, and one summary
// toast reporting how many succeeded vs failed. Mirrors useEntityCrud's toast
// conventions so bulk + single delete feel identical.
export function useBulkDelete({ noun, nounPlural, remove }: UseBulkDeleteArgs): BulkDeleteController {
  const [isDeleting, setIsDeleting] = useState(false);
  const [progress, setProgress] = useState<BulkDeleteProgress | null>(null);
  const plural = nounPlural ?? `${noun}s`;

  const run = async (ids: readonly string[]) => {
    if (ids.length === 0) return null;
    const label = ids.length === 1 ? noun : plural;
    const ok = await confirm({
      title: `Delete ${ids.length} ${label}?`,
      body: `${ids.length} ${label} will be permanently removed.`,
      confirmLabel: `Delete ${ids.length} ${label}`,
    });
    if (!ok) {
      return null;
    }

    setIsDeleting(true);
    setProgress({ done: 0, total: ids.length });

    let succeeded = 0;
    let failed = 0;

    // Sequential so a partial failure (e.g. a 403 on one row) leaves the rest
    // intact and we can report an accurate count.
    for (let i = 0; i < ids.length; i += 1) {
      try {
        await remove(ids[i]).unwrap();
        succeeded += 1;
      } catch {
        failed += 1;
      }
      setProgress({ done: i + 1, total: ids.length });
    }

    setIsDeleting(false);
    setProgress(null);

    if (failed === 0) {
      toast.success(`Deleted ${succeeded} ${succeeded === 1 ? noun : plural}`);
    } else if (succeeded === 0) {
      toast.error(`Could not delete ${failed} ${failed === 1 ? noun : plural}`);
    } else {
      toast.warning(`Deleted ${succeeded}, failed ${failed}`);
    }

    return { succeeded, failed };
  };

  return { isDeleting, progress, run };
}

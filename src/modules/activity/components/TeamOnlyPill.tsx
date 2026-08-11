import { EyeOff } from 'lucide-react';
import { Pill } from '@/shared/ui/data-display';

/**
 * The marker on a note whose `isFamilySensitive` flag is set.
 *
 * One component rather than the same three lines in each list, because the WORDING
 * is the load-bearing part. `isFamilySensitive` is a classification, not an access
 * control — every teammate who can read the note reads it either way (see
 * Note.isFamilySensitive in the backend entity). A surface that drifted to
 * "Private" or "Restricted" would tell staff the note is hidden from someone, and
 * they would then write to it as though it were.
 *
 * Rendered on both surfaces that show notes to the team: the record-level touch
 * log and the Notes screen.
 */
export function TeamOnlyPill() {
  return (
    <Pill tone="y">
      <EyeOff className="mr-1 inline h-3 w-3" />
      Team only
    </Pill>
  );
}

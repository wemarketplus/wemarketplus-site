import { FlaskConical } from 'lucide-react';

// Marks a section (or a whole page) whose data is still sample/fixture content
// because the backend does not expose a matching endpoint yet. Keeps the
// distinction between live and preview data explicit for the platform owner.
interface OwnerPreviewNoticeProps {
  label?: string;
}

export function OwnerPreviewNotice({ label }: OwnerPreviewNoticeProps) {
  return (
    <div className="inline-flex items-center gap-1.5 rounded-pill border border-warning/30 bg-warning/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-warning">
      <FlaskConical className="h-3 w-3" />
      {label ?? 'Preview data'}
    </div>
  );
}

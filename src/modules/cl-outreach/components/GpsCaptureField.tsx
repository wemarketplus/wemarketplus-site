import { MapPin } from 'lucide-react';
import { Button, Label } from '@/shared/ui/core';
import { useGpsCapture } from '../hooks/useGpsCapture';

interface GpsCaptureFieldProps {
  lat: string;
  lng: string;
  onCapture: (lat: string, lng: string) => void;
  onClear: () => void;
}

/**
 * The "Capture GPS" control on the outreach visit form.
 *
 * Its own component rather than another `EntityField` descriptor because the
 * entity kit's field types are all INPUTS — text, select, lookup, readonly — and
 * this is a button whose side effect writes two hidden values. Rendered through
 * EntityFormModal's `footerNote` slot, which already spans both grid columns.
 *
 * Presentational + one hook: the captured pair is written straight back to the
 * form via `onCapture`, so the form stays the single source of truth and editing a
 * visit that already has coordinates shows them without a second copy anywhere.
 */
export function GpsCaptureField({
  lat,
  lng,
  onCapture,
  onClear,
}: GpsCaptureFieldProps) {
  const { status, error, capture } = useGpsCapture();
  const hasFix = Boolean(lat && lng);

  const onClick = async () => {
    const fix = await capture();
    if (fix) onCapture(String(fix.lat), String(fix.lng));
  };

  return (
    <div className="space-y-1.5 rounded-[12px] border border-border/[0.1] bg-surface p-3.5">
      <Label>Location</Label>
      <div className="flex flex-wrap items-center gap-2.5">
        <Button
          variant="secondary"
          size="sm"
          onClick={onClick}
          disabled={status === 'detecting'}
        >
          <MapPin className="h-4 w-4" />
          {status === 'detecting'
            ? 'Detecting…'
            : hasFix
              ? 'Re-capture GPS'
              : 'Capture GPS'}
        </Button>
        {hasFix ? (
          <>
            <span className="font-mono text-[11px] text-muted">
              {lat}, {lng}
            </span>
            {/* A wrong fix — captured in the car park, or at the previous stop —
                has to be removable, or the only way to correct it is to delete
                the visit and log it again. */}
            <button
              type="button"
              onClick={onClear}
              className="text-[11px] font-semibold text-muted underline-offset-2 hover:text-foreground hover:underline"
            >
              Clear
            </button>
          </>
        ) : (
          <span className="text-[11px] text-muted-soft">
            Optional — the visit saves without it.
          </span>
        )}
      </div>
      {error && <p className="text-[11px] text-warning">{error}</p>}
    </div>
  );
}

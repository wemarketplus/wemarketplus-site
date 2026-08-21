import { useState } from 'react';
import { createPortal } from 'react-dom';
import { MapPin, X } from 'lucide-react';
import { Input, Label } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { formatCoords } from '../utils/mercator';
import { LocationPickerModal } from './LocationPickerModal';
import { EMPTY_LOCATION, type LocationValue } from '../types/geocodingTypes';

interface LocationFieldProps {
  id: string;
  label: string;
  value: LocationValue;
  onChange: (value: LocationValue) => void;
  placeholder?: string;
}

/**
 * A form field whose value is a place: reads like the text input it replaces,
 * opens a map picker when touched.
 *
 * It IS `<Input>`, marked read-only, rather than a button styled to look like
 * one. That keeps the field pixel-identical to the Date/Purpose/Miles inputs
 * beside it in the mileage grid (one component, one set of focus and disabled
 * styles, one set of responsive rules), and it keeps the field in the tab order
 * with a label a screen reader already announces correctly.
 *
 * The pin on the right is filled when coordinates are attached and hollow when
 * the value is only text — which is what a trip logged before the picker
 * existed, or one restored from an older row, still looks like.
 */
export function LocationField({
  id,
  label,
  value,
  onChange,
  placeholder,
}: LocationFieldProps) {
  const [open, setOpen] = useState(false);
  const hasCoords = value.coords !== null;

  return (
    // NO `space-y` here: `Label` already owns the label-to-field gap (`mb-1.5`),
    // and adding a second 6px on top of it is what made this field sit LOWER
    // than the plain `<Label> + <Select>` cell beside it in the appointment and
    // Book-tour modals — visibly out of line in a two-column row.
    //
    // So the gap is exactly one rule, the same one every other field in the app
    // gets: whatever `Label` carries. The two pages that used to pair a
    // `space-y-1.5` cell with this component (Mileage, EVV) had the doubled gap
    // on their OWN inputs too, and were corrected to match rather than this
    // component being bent to fit them.
    //
    // `flex flex-col` stays, so the wrapper stretches predictably as a grid item
    // and the label's margin can never collapse into a caller's spacing.
    <div className="flex flex-col">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Input
          id={id}
          value={value.label}
          placeholder={placeholder}
          // Read-only, not disabled: disabled would drop it out of the tab order
          // and grey it out, and this field is neither unavailable nor empty of
          // meaning — it is simply set through the picker.
          readOnly
          aria-haspopup="dialog"
          title={hasCoords && value.coords ? formatCoords(value.coords) : undefined}
          onClick={() => setOpen(true)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' || event.key === ' ') {
              event.preventDefault();
              setOpen(true);
            }
          }}
          className={cn('cursor-pointer', value.label ? 'pr-16' : 'pr-10')}
        />
        <div className="absolute right-2 top-1/2 flex -translate-y-1/2 items-center gap-0.5">
          {value.label && (
            // A wrong endpoint has to be removable without deleting the whole
            // half-filled trip and starting again.
            <button
              type="button"
              aria-label={`Clear ${label.toLowerCase()}`}
              onClick={() => onChange(EMPTY_LOCATION)}
              className="flex h-6 w-6 items-center justify-center rounded-full text-muted-soft hover:bg-foreground/[0.06] hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            aria-label={`Choose ${label.toLowerCase()} on a map`}
            onClick={() => setOpen(true)}
            className="flex h-6 w-6 items-center justify-center rounded-full hover:bg-foreground/[0.06]"
          >
            <MapPin
              className={cn(
                'h-4 w-4',
                hasCoords ? 'text-primary' : 'text-muted-soft',
              )}
            />
          </button>
        </div>
      </div>

      {/* Mounted only while open: two of these live on the mileage form, and a
          closed picker still holding a map's worth of tile <img> elements is a
          cost paid on a screen that mostly just lists trips.
          
          PORTALLED to <body> because this field is used INSIDE other modals (the
          appointment and visit forms). Those panels animate in with a transform,
          and a transformed ancestor makes `position: fixed` resolve against it
          rather than the viewport — so without the portal the picker renders
          clipped inside the form it was opened from, map cut in half. */}
      {open &&
        createPortal(
          <LocationPickerModal
            open={open}
            onClose={() => setOpen(false)}
            title={label}
            value={value}
            onSelect={onChange}
          />,
          document.body,
        )}
    </div>
  );
}

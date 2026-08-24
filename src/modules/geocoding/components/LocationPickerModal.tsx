import { useEffect, useMemo, useState } from 'react';
import { Crosshair, Loader2, MapPin } from 'lucide-react';
import { useDebounce, useGpsCapture } from '@/shared/hooks';
import { Button, Input, Label, SearchInput } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { cn } from '@/shared/utils/cn';
import {
  useLazyReverseGeocodeQuery,
  useSearchPlacesQuery,
} from '../api/geocodingApi';
import {
  PLACE_ZOOM,
  SEARCH_DEBOUNCE_MS,
  SEARCH_MIN_CHARS,
  WORLD_VIEW_CENTER,
  WORLD_VIEW_ZOOM,
} from '../constants/mapConstants';
import { formatCoords } from '../utils/mercator';
import { MapCanvas, type MapView } from './MapCanvas';
import type { LatLng, LocationValue, PlaceResult } from '../types/geocodingTypes';

interface LocationPickerModalProps {
  open: boolean;
  onClose: () => void;
  /** Names the endpoint being set, e.g. "From" — the dialog's title. */
  title: string;
  /** The field's current value, so reopening resumes where it left off. */
  value: LocationValue;
  onSelect: (value: LocationValue) => void;
}

const worldView: MapView = {
  center: WORLD_VIEW_CENTER,
  zoom: WORLD_VIEW_ZOOM,
};

/**
 * Search, map, pin, confirm — the whole location picker.
 *
 * Three ways in, because a field worker's answer to "where was this?" arrives in
 * three different shapes: they know the name (search), they know the spot but
 * not its name (tap the map), or they are standing in it (use my location). All
 * three end in the same place: a label a reviewer can read and an exact pair of
 * coordinates.
 *
 * NOTHING IS INVENTED. The map opens on the world, not on a stand-in city, and
 * a point the geocoder cannot name keeps its coordinates as its label rather
 * than being given a plausible-looking address it does not have.
 */
export function LocationPickerModal({
  open,
  onClose,
  title,
  value,
  onSelect,
}: LocationPickerModalProps) {
  const [query, setQuery] = useState('');
  const [showResults, setShowResults] = useState(false);
  const [coords, setCoords] = useState<LatLng | null>(value.coords);
  const [label, setLabel] = useState(value.label);
  /** What the map is asked to show. Its own pan/zoom lives inside MapCanvas. */
  const [view, setView] = useState<MapView>(worldView);
  /** Where the map actually is, used to bias search toward the visible area. */
  const [visible, setVisible] = useState<MapView>(worldView);

  const { status: gpsStatus, error: gpsError, capture } = useGpsCapture();
  const [reverse, { isFetching: isResolvingAddress }] =
    useLazyReverseGeocodeQuery();

  // Reopening for the OTHER endpoint must not inherit the first one's pin: From
  // and To share this component, and a trip that starts and ends in the same
  // place because the dialog kept its last answer is a wrong reimbursement.
  useEffect(() => {
    if (!open) return;
    setQuery('');
    setShowResults(false);
    setCoords(value.coords);
    setLabel(value.label);
    const opening = value.coords
      ? { center: value.coords, zoom: PLACE_ZOOM }
      : worldView;
    setView(opening);
    setVisible(opening);
  }, [open, value.coords, value.label]);

  /**
   * Centre on the user when the browser ALREADY has permission.
   *
   * Deliberately silent, and deliberately does not drop a pin: it only replaces
   * a world view with a useful one. Asking for the permission here instead would
   * fire a browser prompt at someone who opened the dialog to type an address —
   * so the prompt lives on the "Use my location" button, where it is an answer
   * to something they asked for.
   */
  useEffect(() => {
    if (!open || value.coords) return;
    let cancelled = false;
    void (async () => {
      try {
        const permission = await navigator.permissions?.query({
          name: 'geolocation' as PermissionName,
        });
        if (permission?.state !== 'granted') return;
      } catch {
        // Permissions API missing or blocked (older Safari) — no prompt-free
        // way to know, so leave the world view alone.
        return;
      }
      const fix = await capture();
      if (!fix || cancelled) return;
      setView({ center: fix, zoom: PLACE_ZOOM });
    })();
    return () => {
      cancelled = true;
    };
  }, [open, value.coords, capture]);

  const debouncedQuery = useDebounce(query.trim(), SEARCH_DEBOUNCE_MS);
  const canSearch = debouncedQuery.length >= SEARCH_MIN_CHARS;
  const {
    data: results,
    isFetching: isSearching,
    isError: searchFailed,
  } = useSearchPlacesQuery(
    {
      q: debouncedQuery,
      viewLat: visible.zoom > WORLD_VIEW_ZOOM ? visible.center.lat : undefined,
      viewLng: visible.zoom > WORLD_VIEW_ZOOM ? visible.center.lng : undefined,
    },
    { skip: !open || !canSearch },
  );

  /** Set the pin, then name it from whatever the geocoder knows about the point. */
  const pickPoint = async (point: LatLng) => {
    setCoords(point);
    setShowResults(false);
    // The coordinates are the answer; the address is a courtesy. Showing them
    // immediately means a tap is never waiting on a network round trip, and a
    // point the provider cannot name keeps a label that is exactly true.
    setLabel(formatCoords(point));
    try {
      const place = await reverse(point).unwrap();
      if (place) setLabel(place.name || place.label);
    } catch {
      // Provider down or rate-limited. The pin stands, named by its coordinates.
    }
  };

  const choosePlace = (place: PlaceResult) => {
    const point = { lat: place.lat, lng: place.lng };
    setCoords(point);
    setLabel(place.name || place.label);
    setQuery(place.name || place.label);
    setShowResults(false);
    setView({ center: point, zoom: PLACE_ZOOM });
  };

  const useMyLocation = async () => {
    const fix = await capture();
    if (!fix) return;
    setView({ center: fix, zoom: PLACE_ZOOM });
    await pickPoint(fix);
  };

  const confirm = () => {
    if (!coords) return;
    // A blanked label falls back to the coordinates rather than to "" — an
    // endpoint with no name at all reads as a missing location on the trip table.
    onSelect({ label: label.trim() || formatCoords(coords), coords });
    onClose();
  };

  const emptyHint = useMemo(() => {
    if (searchFailed) return 'Address lookup is unavailable right now.';
    if (isSearching) return 'Searching…';
    if (canSearch && results?.length === 0) return 'No places matched that.';
    return null;
  }, [searchFailed, isSearching, canSearch, results]);

  // "From" → "From location", but "Location" stays "Location": the field's own
  // label is the title, and blindly appending gave the appointment form a dialog
  // headed "Location location".
  const heading = /location/i.test(title) ? title : `${title} location`;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={heading}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={confirm} disabled={!coords}>
            <MapPin className="h-4 w-4" />
            Select location
          </Button>
        </>
      }
    >
      <div className="space-y-3.5">
        {/* flex, for the same reason as LocationField: the wrapped input below
            would otherwise collapse its margin against the label's. */}
        <div className="flex flex-col space-y-1.5">
          <Label htmlFor="location-search">Search for an address or place</Label>
          {/*
            <SearchInput>, not a hand-rolled search field. This was the last
            copy of that markup in the app and it had drifted on both of the
            things SearchInput exists to pin down:

              · the icon was centred with `top-1/2 -translate-y-1/2`, which
                rounds to a half-pixel at some zoom levels and heights — the
                faint "search icon sits a hair high" misalignment SearchInput's
                `inset-y-0` + flex centring avoids;
              · the glyph was `text-muted-soft`, a step lighter than the
                `text-muted` every other search field in the app uses.

            So the one search field inside a dialog looked subtly different from
            the nineteen on the list pages behind it.
          */}
          <div className="relative">
            <SearchInput
              id="location-search"
              value={query}
              onChange={(next) => {
                setQuery(next);
                setShowResults(true);
              }}
              // Enter must not submit anything: results arrive on their own, and
              // the only commit in this dialog is the button in the footer.
              onKeyDown={(event) => {
                if (event.key === 'Enter') event.preventDefault();
              }}
              placeholder="Mercy General Hospital, 4001 J St…"
              autoComplete="off"
              // SearchInput already reserves `pr-9` for its own clear button
              // once there is a value. While a lookup is in flight the spinner
              // needs a second slot of the same width beside it, or the two
              // land on top of each other.
              className={isSearching ? 'pr-[4.5rem]' : undefined}
            />
            {isSearching && (
              // `right-9` = just left of the clear button's 36px slot. Centred
              // with `inset-y-0` + `my-auto`, the same way SearchInput centres
              // its own two glyphs, so all three agree on the centre line.
              <Loader2 className="pointer-events-none absolute inset-y-0 right-9 my-auto h-4 w-4 animate-spin text-muted" />
            )}
          </div>

          {showResults && canSearch && (
            <div className="max-h-44 overflow-y-auto rounded-md border border-border/[0.12] bg-surface-raised">
              {(results ?? []).map((place) => (
                <button
                  key={place.id}
                  type="button"
                  onClick={() => choosePlace(place)}
                  className="flex w-full items-start gap-2.5 border-b border-border/[0.07] px-3 py-2.5 text-left last:border-b-0 hover:bg-foreground/[0.05]"
                >
                  <MapPin className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
                  <span className="min-w-0">
                    <span className="block truncate text-[13px] font-bold text-foreground">
                      {place.name}
                    </span>
                    <span className="block truncate text-[11px] text-muted">
                      {place.label}
                    </span>
                  </span>
                </button>
              ))}
              {emptyHint && (
                <p className="px-3 py-2.5 text-[12px] text-muted">{emptyHint}</p>
              )}
            </div>
          )}
        </div>

        <MapCanvas
          view={view}
          marker={coords}
          onPick={pickPoint}
          onViewChange={setVisible}
          className="h-[260px] w-full sm:h-[320px]"
        />

        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={useMyLocation}
            disabled={gpsStatus === 'detecting'}
          >
            <Crosshair className="h-4 w-4" />
            {gpsStatus === 'detecting' ? 'Locating…' : 'Use my location'}
          </Button>
          <p className="text-[11px] text-muted-soft">
            Tap the map to move the pin.
          </p>
        </div>
        {gpsError && <p className="text-[11px] text-warning">{gpsError}</p>}

        <div className="space-y-1.5 rounded-lg border border-border/[0.1] bg-surface p-3.5">
          <Label htmlFor="location-label">Saved as</Label>
          {/* Editable on purpose. The geocoder's answer for the office car park
              is a street address; what belongs on an expense claim is "Office".
              The NAME is what people read — the coordinates below are what the
              system stores, and they do not change when this is renamed. */}
          <Input
            id="location-label"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            placeholder="Office"
            disabled={!coords}
          />
          <p
            className={cn(
              'font-mono text-[11px]',
              coords ? 'text-muted' : 'text-muted-soft',
            )}
          >
            {coords
              ? formatCoords(coords)
              : 'No point chosen yet — search, tap the map, or use your location.'}
            {isResolvingAddress && coords && ' · looking up address…'}
          </p>
        </div>
      </div>
    </Modal>
  );
}

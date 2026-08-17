import { useCallback, useState } from 'react';

export type GpsStatus = 'idle' | 'detecting' | 'ready' | 'error';

export interface GpsFix {
  lat: number;
  lng: number;
}

// The column is numeric(10,7), and the DTO validates @IsNumber({ maxDecimalPlaces: 7 }),
// so a raw reading (which can carry a dozen decimals) has to be rounded before it
// is submitted or the request 400s.
const GPS_PRECISION = 7;

const round = (value: number): number => Number(value.toFixed(GPS_PRECISION));

/**
 * navigator.geolocation for the "Capture GPS" button on the outreach check-in form.
 *
 * `cl_outreach_visits` has carried `gpsLat`/`gpsLng` columns, and the create DTO has
 * accepted them, since the table was written — nothing ever sent them. The check-in
 * screen rendered a coordinate line that was empty on every row for every tenant,
 * because the only way to file a visit was a form with no GPS control on it.
 *
 * Promise-based rather than holding the coordinates itself: the FORM owns the value
 * (it is submitted with the rest of the visit), so a second copy in here would be a
 * second source of truth that has to be kept in step with editing an existing row.
 * This hook owns only the transient status the button renders.
 *
 * Resolves to null rather than rejecting on denial. A refused permission is an
 * ordinary answer — the marketer is indoors, or said no — and the visit is still
 * worth logging without coordinates, so it must not become an exception the caller
 * has to catch to keep the form usable.
 */
export function useGpsCapture() {
  const [status, setStatus] = useState<GpsStatus>('idle');
  const [error, setError] = useState<string | null>(null);

  const capture = useCallback((): Promise<GpsFix | null> => {
    if (!navigator.geolocation) {
      setStatus('error');
      setError('This browser cannot report a location.');
      return Promise.resolve(null);
    }
    setStatus('detecting');
    setError(null);
    return new Promise((resolve) => {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          setStatus('ready');
          resolve({
            lat: round(position.coords.latitude),
            lng: round(position.coords.longitude),
          });
        },
        (err) => {
          setStatus('error');
          setError(
            err.code === err.PERMISSION_DENIED
              ? 'Location permission denied. You can still save the visit without it.'
              : 'Could not read your location. You can still save the visit without it.',
          );
          resolve(null);
        },
        // A field worker is standing outside a building waiting for this, so cap
        // the wait; a minute-old fix from walking in is close enough to the door.
        { enableHighAccuracy: true, timeout: 10_000, maximumAge: 60_000 },
      );
    });
  }, []);

  return { status, error, capture };
}

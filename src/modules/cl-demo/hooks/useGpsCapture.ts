// Wraps navigator.geolocation for the GPS Check-In tab's "Capture GPS" button.
// Returns the captured "lat, lng" string plus a status, mirroring the
// reference captureGPS().
import { useCallback, useState } from 'react';

export function useGpsCapture() {
  const [coords, setCoords] = useState('');
  const [status, setStatus] = useState<'idle' | 'detecting' | 'ready' | 'error'>('idle');

  const capture = useCallback(() => {
    if (!navigator.geolocation) {
      setCoords('GPS not available');
      setStatus('error');
      return;
    }
    setCoords('Detecting…');
    setStatus('detecting');
    navigator.geolocation.getCurrentPosition(
      (p) => {
        setCoords(p.coords.latitude.toFixed(5) + ', ' + p.coords.longitude.toFixed(5));
        setStatus('ready');
      },
      () => {
        setCoords('Permission denied');
        setStatus('error');
      },
    );
  }, []);

  return { coords, status, capture };
}

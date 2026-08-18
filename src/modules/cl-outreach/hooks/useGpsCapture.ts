/**
 * The GPS hook now lives in shared/hooks — the mileage map picker needs the same
 * permission handling, and two copies is how one of them drifts.
 *
 * Re-exported from its original path so the outreach check-in form's import (and
 * any half-finished branch touching it) keeps working.
 */
export { useGpsCapture, type GpsFix, type GpsStatus } from '@/shared/hooks';

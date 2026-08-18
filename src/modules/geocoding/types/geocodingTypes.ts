/** A point on the map. The one coordinate shape the whole module passes around. */
export interface LatLng {
  lat: number;
  lng: number;
}

/** Mirrors wemarketplus-backend/src/geocoding/dto/place-result.dto.ts. */
export interface PlaceResult {
  /** Stable within one response only — a React key, never a stored reference. */
  id: string;
  /** Short name of the place, e.g. "Mercy General Hospital". */
  name: string;
  /** Full postal-style description, shown as the secondary line in the list. */
  label: string;
  lat: number;
  lng: number;
}

/**
 * What a location field holds: what a person reads, plus where it actually is.
 *
 * The two are kept together because they are only meaningful together. The label
 * is what an expense reviewer sees on a claim ("Office", "Mercy General") and is
 * the ONLY thing rows written before the picker existed have; the coordinates
 * are what tells two workers' "clinic" apart.
 *
 * `coords: null` is a legitimate value — a trip loaded from before the picker, or
 * a label typed by hand — and is stored as null on BOTH halves of the pair, never
 * as 0,0.
 */
export interface LocationValue {
  label: string;
  coords: LatLng | null;
}

/** The empty field value. */
export const EMPTY_LOCATION: LocationValue = { label: '', coords: null };

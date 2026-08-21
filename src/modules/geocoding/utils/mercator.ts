import type { LatLng } from '../types/geocodingTypes';

/** Edge length of one raster tile, in CSS pixels. 256 is universal for XYZ tiles. */
export const TILE_SIZE = 256;

/**
 * Latitude beyond which Web Mercator's projection runs to infinity. Every XYZ
 * tile scheme cuts the world off here, which is why the poles are not on the map.
 */
const MAX_LATITUDE = 85.05112878;

/** Coordinates stored/submitted with 7 decimals — see the mileage DTOs. */
const GPS_DECIMAL_PLACES = 7;

export const roundCoord = (value: number): number =>
  Number(value.toFixed(GPS_DECIMAL_PLACES));

export const clamp = (value: number, min: number, max: number): number =>
  Math.min(max, Math.max(min, value));

/** A point in the tile pyramid's pixel space at a given zoom. */
export interface WorldPoint {
  x: number;
  y: number;
}

/**
 * lat/lng → world pixels at `zoom` (spherical Web Mercator, EPSG:3857).
 *
 * This module is the whole "map engine": four functions of arithmetic, drawn on
 * by MapCanvas as absolutely-positioned <img> tiles. That is a deliberate choice
 * over adding Leaflet or MapLibre — the app has NO map dependency today, ships a
 * hand-built UI kit rather than a component library (see shared/ui), and the
 * picker needs exactly pan, zoom, one marker and a click handler. A tile
 * renderer for that is this file plus one component; a map library is 140kB and
 * an imperative instance to keep in step with React state.
 *
 * If the product later needs routes, clusters, polygons or vector styles, this
 * is the seam to replace: swap MapCanvas for a library-backed component and
 * nothing outside it changes, because every other file here speaks only
 * lat/lng.
 */
export function project(point: LatLng, zoom: number): WorldPoint {
  const scale = TILE_SIZE * 2 ** zoom;
  const lat = clamp(point.lat, -MAX_LATITUDE, MAX_LATITUDE);
  const sin = Math.sin((lat * Math.PI) / 180);
  return {
    x: ((point.lng + 180) / 360) * scale,
    y: (0.5 - Math.log((1 + sin) / (1 - sin)) / (4 * Math.PI)) * scale,
  };
}

/** World pixels at `zoom` → lat/lng. The exact inverse of `project`. */
export function unproject(point: WorldPoint, zoom: number): LatLng {
  const scale = TILE_SIZE * 2 ** zoom;
  const n = Math.PI - (2 * Math.PI * point.y) / scale;
  return {
    // Longitude wraps rather than clamps: dragging west past the date line is a
    // normal gesture, and 190° must come back as -170°, not stop at 180°.
    lng: wrapLongitude((point.x / scale) * 360 - 180),
    lat: (180 / Math.PI) * Math.atan(0.5 * (Math.exp(n) - Math.exp(-n))),
  };
}

export function wrapLongitude(lng: number): number {
  return ((((lng + 180) % 360) + 360) % 360) - 180;
}

/** How a fix is shown wherever the app displays raw coordinates. */
export const formatCoords = (point: LatLng): string =>
  `${point.lat.toFixed(5)}, ${point.lng.toFixed(5)}`;

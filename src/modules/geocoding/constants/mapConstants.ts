import type { LatLng } from '../types/geocodingTypes';

/**
 * Raster tile template for the picker's map.
 *
 * Defaults to OpenStreetMap's own tile server, which needs no key and no
 * account — the right default for dev and for a small deployment, and the same
 * data the default geocoder answers from, so a search hit and the map under it
 * always agree.
 *
 * OSM's tile usage policy forbids heavy or commercial traffic. A deployment
 * with a real field team sets VITE_MAP_TILE_URL to a tile provider of its own
 * (MapTiler, Stadia, Thunderforest, a self-hosted renderer) with the key already
 * in the template — e.g.
 *   VITE_MAP_TILE_URL=https://api.maptiler.com/maps/streets-v2/{z}/{x}/{y}.png?key=XXXX
 * and VITE_MAP_ATTRIBUTION to whatever that provider requires be displayed.
 *
 * NOTE the tile key, unlike the geocoder's, is necessarily public: tiles are
 * <img> requests from the browser. Restrict it by HTTP referrer in the
 * provider's console rather than treating it as a secret.
 */
export const MAP_TILE_URL =
  import.meta.env.VITE_MAP_TILE_URL ||
  'https://tile.openstreetmap.org/{z}/{x}/{y}.png';

/** Credit line drawn over the map. Required by OSM, and by every alternative. */
export const MAP_ATTRIBUTION =
  import.meta.env.VITE_MAP_ATTRIBUTION || '© OpenStreetMap contributors';

export const MAP_ATTRIBUTION_URL = 'https://www.openstreetmap.org/copyright';

export const MIN_ZOOM = 2;
/** OSM's raster tiles stop at 19; asking for 20 serves blank squares. */
export const MAX_ZOOM = 19;

/**
 * Opening view when the field is empty and the browser will not say where the
 * user is: the whole world, centred on 0,0.
 *
 * NOT a city, a head office, or any other stand-in. A map that opens on an
 * invented place looks like it knows something it does not, and a hurried
 * worker confirming a pin near that centre would file a trip from a location
 * nobody chose. A world view is unmistakably "tell me where".
 */
export const WORLD_VIEW_CENTER: LatLng = { lat: 0, lng: 0 };
export const WORLD_VIEW_ZOOM = MIN_ZOOM;

/** Zoom used when the map jumps to a picked place or a GPS fix. */
export const PLACE_ZOOM = 16;

/** Shortest query sent for autocomplete — matches the server's @MinLength. */
export const SEARCH_MIN_CHARS = 3;

/**
 * Typing pause before a search is issued. Long by UI standards on purpose: the
 * default provider allows about one request a second across the whole
 * deployment, and every keystroke that does not become a request is budget left
 * for the next person on the road.
 */
export const SEARCH_DEBOUNCE_MS = 450;

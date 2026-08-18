/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_APP_NAME?: string;
  /**
   * Raster tile template for the location picker's map, e.g.
   * `https://api.maptiler.com/maps/streets-v2/{z}/{x}/{y}.png?key=XXX`.
   * Unset falls back to OpenStreetMap's own tiles, which need no key — see
   * modules/geocoding/constants/mapConstants.ts.
   */
  readonly VITE_MAP_TILE_URL?: string;
  /** Credit line drawn over the map. Required by every tile provider. */
  readonly VITE_MAP_ATTRIBUTION?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

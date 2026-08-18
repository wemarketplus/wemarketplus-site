// Address lookup and the map/location picker built on it.
//
// Shared infrastructure, not a screen: it has no route and no page of its own.
// Any form with a "where?" field mounts <LocationField>, which is what the
// mileage Log-trip form's From and To now are — one screen serving BOTH products
// (/field/mileage is HospiceLink's and CommunityLink's field surface alike).
//
// The provider is reached through the SERVER (/api/geocoding/*), never from the
// browser — see api/geocodingApi.ts for why.
export { geocodingApi, useSearchPlacesQuery, useLazyReverseGeocodeQuery } from './api/geocodingApi';
export { LocationField } from './components/LocationField';
export { LocationPickerModal } from './components/LocationPickerModal';
export { MapCanvas, type MapView } from './components/MapCanvas';
export { formatCoords, roundCoord } from './utils/mercator';
export {
  fromLocationValue,
  toLocationValue,
  sameCoords,
} from './utils/locationValue';
export { EMPTY_LOCATION } from './types/geocodingTypes';
export type { LatLng, LocationValue, PlaceResult } from './types/geocodingTypes';

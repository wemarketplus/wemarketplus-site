import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { LatLng, PlaceResult } from '../types/geocodingTypes';

// Verified against wemarketplus-backend/src/geocoding/geocoding.controller.ts:
//   GET /geocoding/search?q&limit&viewLat&viewLng
//   GET /geocoding/reverse?lat&lng
//
// The provider is called by the SERVER, never from here: it requires an
// identifying User-Agent (which a browser cannot set, and this app sends
// `no-referrer` app-wide besides), a commercial provider's key would be public
// in this bundle, and the rate limit is per deployment — see the service.

const env = <T>(res: ApiEnvelope<T>) => res.data;

/**
 * An address does not move. Ten minutes of cache turns re-opening the picker,
 * or correcting a trip's To after its From, into zero provider calls — which
 * matters here more than on other screens, because the default provider allows
 * roughly one request per second for the whole deployment.
 */
const ADDRESS_CACHE_SECONDS = 600;

export const geocodingApi = createApi({
  reducerPath: 'geocodingApi',
  baseQuery: baseQueryWithReauth,
  // No tagTypes: nothing here is mutable. These are lookups against a read-only
  // external service, so there is no write that could invalidate them.
  keepUnusedDataFor: ADDRESS_CACHE_SECONDS,
  endpoints: (build) => ({
    /**
     * Autocomplete for the picker's search field.
     *
     * `viewLat`/`viewLng` bias results toward what the user is looking at, so
     * "mercy general" finds the one across town before the forty elsewhere.
     * Both are optional and RTK Query drops undefined params, so an unbiased
     * search sends neither.
     */
    searchPlaces: build.query<
      PlaceResult[],
      { q: string; limit?: number; viewLat?: number; viewLng?: number }
    >({
      query: (params) => ({ url: '/geocoding/search', params }),
      transformResponse: env<PlaceResult[]>,
    }),

    /**
     * The address at a point — what a tap on the map or a GPS fix is turned
     * into before it is shown in the field.
     *
     * Resolves to null where the provider knows nothing about the point. That
     * is an ordinary answer, not a failure: the coordinates the user chose are
     * still exact and still stored, they just have no street name.
     */
    reverseGeocode: build.query<PlaceResult | null, LatLng>({
      query: ({ lat, lng }) => ({ url: '/geocoding/reverse', params: { lat, lng } }),
      transformResponse: env<PlaceResult | null>,
    }),
  }),
});

export const {
  useSearchPlacesQuery,
  useLazyReverseGeocodeQuery,
} = geocodingApi;

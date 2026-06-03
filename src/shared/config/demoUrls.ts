// CommunityLink demo destinations — the in-app demo routes. These are the
// exact same paths the CommunityLink nav dropdown / plan cards use, so the
// HospiceLink demo links point at the identical pages. Every HospiceLink nav
// menu, plan card and CTA links here, and the legacy /demo/hospicelink/{pro,
// max,gold} paths redirect to the matching route below.
export const COMMUNITYLINK_DEMO_URLS = {
  pro: '/demo/communitylink/pro',
  gold: '/demo/communitylink/gold',
  max: '/demo/communitylink/max',
} as const;

// Legacy HospiceLink demo paths kept only so old links/bookmarks still resolve.
// The router maps each to its CommunityLink replacement via <Navigate replace>.
export const LEGACY_DEMO_REDIRECTS: ReadonlyArray<{ from: string; to: string }> = [
  { from: '/demo/hospicelink/pro', to: COMMUNITYLINK_DEMO_URLS.pro },
  { from: '/demo/hospicelink/max', to: COMMUNITYLINK_DEMO_URLS.max },
  { from: '/demo/hospicelink/gold', to: COMMUNITYLINK_DEMO_URLS.gold },
];

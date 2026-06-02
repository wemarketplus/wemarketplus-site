import { MarketingShell } from '../components/MarketingShell';
import { CommunityOverview } from '../components/sections/CommunityOverview';

// /communitylink mirrors the live site's #communitylink block: senior-living
// hero divider, value pillars, the 8-tile feature grid, and per-facility
// pricing — all in CommunityOverview.
export function CommunityLinkLandingPage() {
  return (
    <MarketingShell>
      <CommunityOverview />
    </MarketingShell>
  );
}

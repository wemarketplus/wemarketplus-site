// Types backing the verbatim landing-page content (constants/landingContent.ts
// and constants/platformPreviewContent.ts). Kept here so the constants files
// hold data only and section components import their shapes from one place.

export interface Metric {
  value: string;
  label: string;
  tone: 'sage' | 'azure' | 'amber' | 'purple';
}

export type FeatureIcon =
  | 'pipeline'
  | 'alert'
  | 'map'
  | 'ai'
  | 'mileage'
  | 'windshield'
  | 'revenue'
  | 'triage'
  | 'audit'
  | 'phone';

export interface FeatureCard {
  title: string;
  body: string;
  badge: string;
  tone: 'azure' | 'red' | 'sage' | 'purple' | 'amber';
  icon: FeatureIcon;
}

export interface HowStep {
  num: string;
  title: string;
  body: string;
}

export interface Testimonial {
  name: string;
  role: string;
  quote: string;
}

export type SecurityIcon =
  | 'encryption'
  | 'baa'
  | 'roles'
  | 'audit'
  | 'uptime'
  | 'guarantee';

export interface SecurityCard {
  title: string;
  body: string;
  icon: SecurityIcon;
}

export interface Faq {
  q: string;
  a: string;
}

export type CommunityPillarIcon = 'sales' | 'operations' | 'financial';

export interface CommunityPillar {
  icon: CommunityPillarIcon;
  title: string;
  body: string;
  tone: 'amber' | 'sage' | 'azure';
}

export interface CommunityTile {
  icon: string;
  title: string;
  body: string;
}

export type TrustBadgeIcon = 'shield' | 'lock' | 'guarantee' | 'clock' | 'phone';

export interface TrustBadge {
  icon: TrustBadgeIcon;
  tone: 'sage' | 'azure' | 'amber';
  title: string;
  sub: string;
}

// --- Live Platform Preview mockup (index.html "See It Before You Buy") ------

export interface PreviewKpi {
  label: string;
  value: string;
  tone: string;
}

export interface PreviewPipelineRow {
  name: string;
  pill: 'r' | 'y' | 'g' | 'b';
  label: string;
  meta: string;
}

export interface PreviewNavGroup {
  group: string;
  items: readonly string[];
}

export interface PreviewFeedItem {
  title: string;
  detail: string;
  when: string;
  dot: string;
}

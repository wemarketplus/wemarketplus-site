import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bot,
  ClipboardList,
  Globe,
  LayoutDashboard,
  LineChart,
  MessageSquare,
  ShieldCheck,
  Sliders,
  Users2,
} from 'lucide-react';
import type { OwnerNavItem } from '../types/ownerPortalTypes';

// Mirrors the sidebar in wemarketplus-site/owner portal. Routes live under
// /owner/* so the owner shell can be nested inside the main router.
export const OWNER_NAV: readonly OwnerNavItem[] = [
  { to: '/owner', screen: 'dashboard', label: 'Command dashboard', icon: LayoutDashboard },
  { to: '/owner/revenue', screen: 'revenue', label: 'Revenue intelligence', icon: BarChart3 },
  { to: '/owner/customers', screen: 'customers', label: 'Customer database', icon: Users2 },
  { to: '/owner/pipeline', screen: 'pipeline', label: 'Sales pipeline', icon: LineChart },
  { to: '/owner/visitors', screen: 'visitors', label: 'Website visitors', icon: Globe },
  { to: '/owner/marketing', screen: 'marketing', label: 'Marketing performance', icon: Activity },
  {
    to: '/owner/churn',
    screen: 'churn',
    label: 'Churn & risk',
    icon: AlertTriangle,
    badge: '3 at risk',
  },
  { to: '/owner/usage', screen: 'usage', label: 'Product usage', icon: ClipboardList },
  { to: '/owner/insights', screen: 'insights', label: 'AI business insights', icon: Bot },
  { to: '/owner/communication', screen: 'communication', label: 'Communication log', icon: MessageSquare },
  { to: '/owner/security', screen: 'security', label: 'Security & audit', icon: ShieldCheck },
  { to: '/owner/admin-controls', screen: 'admin-controls', label: 'Admin controls', icon: Sliders },
];

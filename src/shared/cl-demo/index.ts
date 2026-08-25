// Public surface of the shared CommunityLink demo design system — primitives,
// style tokens, hooks, and types reused by the Pro (cl-demo) and Gold
// (cl-demo-gold) demo modules.
export { Card } from './components/Card';
export { Badge } from './components/Badge';
export { StatTile } from './components/StatTile';
export { StatGrid } from './components/StatGrid';
export { DemoButton } from './components/DemoButton';
export { Field } from './components/Field';
export { DemoSearch } from './components/DemoSearch';
export { DemoToast } from './components/DemoToast';
export { useToastAutohide } from './hooks/useToastAutohide';
// Re-export, not a definition: useCsvDownload moved to shared/hooks when a
// production screen (modules/field's mileage export) started needing it, and
// production must not import from this demo-only design system. Kept on this
// surface so the three demo modules' call sites are untouched.
export { useCsvDownload } from '@/shared/hooks';
export { cap, todayIso } from './utils';
export type { BadgeTone, ToastState } from './types';
export * from './styles';

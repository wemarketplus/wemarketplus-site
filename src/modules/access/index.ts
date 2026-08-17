// Access module: single source of truth for which dashboard(s) a user can open,
// which one is currently active, and which products the tenant is billed for.
// Powers the product switcher, the product-aware navigation, and the
// RequireProduct route guard.
//
// Two distinct questions, deliberately kept apart (see utils/productAccess.ts):
//   switchableProducts / hasProductAccess -> may this session OPEN that
//     dashboard? Both, for every authenticated user.
//   entitledProducts / entitlementForProduct / tierForProduct -> what has the
//     tenant PAID FOR? Drives tier gating only.
export {
  default as accessReducer,
  setActiveProduct,
  clearActiveProduct,
  type AccessState,
} from './store/accessSlice';
export { ViewingAsBadge } from './components/ViewingAsBadge';
export { ProductSwitcher } from './components/ProductSwitcher';
export { useEntitlements } from './hooks/useEntitlements';
export { useActiveProduct } from './hooks/useActiveProduct';
export { useActiveEntitlement } from './hooks/useActiveEntitlement';
export {
  SWITCHABLE_PRODUCTS,
  switchableProducts,
  entitledProducts,
  primaryProduct,
  hasProductAccess,
  resolveActiveProduct,
  entitlementForProduct,
  tierForProduct,
} from './utils/productAccess';

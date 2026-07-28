// Access module: single source of truth for which product(s) a user can use and
// which dashboard is currently active. Powers the product switcher, the
// product-aware navigation, and the RequireProduct route guard.
export {
  default as accessReducer,
  setActiveProduct,
  clearActiveProduct,
  type AccessState,
} from './store/accessSlice';
export { ProductSwitcher } from './components/ProductSwitcher';
export { useEntitlements } from './hooks/useEntitlements';
export { useActiveProduct } from './hooks/useActiveProduct';
export { useActiveEntitlement } from './hooks/useActiveEntitlement';
export {
  entitledProducts,
  primaryProduct,
  hasProductAccess,
  resolveActiveProduct,
  entitlementForProduct,
  tierForProduct,
} from './utils/productAccess';

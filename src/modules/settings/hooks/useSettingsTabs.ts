import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useActiveEntitlement } from '@/modules/access';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import {
  ADMIN_SETTINGS_TABS,
  SETTINGS_TABS,
  SETTINGS_TABS_BY_PRODUCT,
} from '../constants/settingsConstants';
import type { SettingsTab } from '../types/settingsTypes';

/**
 * Which Settings tabs this session actually gets, and which one is showing.
 *
 * Two filters, for two different reasons:
 *
 *  - PRODUCT. `roles` belongs to the CommunityLink Administrator guide only
 *    (see SETTINGS_TABS_BY_PRODUCT).
 *  - ROLE. The /settings route admits CommunityLink's Owner/Investor alongside
 *    Admin/Owner, but the custom-roles endpoints are Admin/Owner-only
 *    server-side. Without this an Owner/Investor would get a tab that answers
 *    403 and renders nothing — a dead tab reads as a broken screen.
 *
 * `activeTab` is RESOLVED, never the raw stored value. The picker is persisted
 * and survives a product switch, so an admin who left Settings on Manage roles
 * and came back on the HospiceLink dashboard would otherwise land on a tab that
 * is no longer in the strip: no button highlighted, no panel rendered. Falling
 * back to the first visible tab keeps the screen coherent without clearing the
 * user's choice — switching back restores it.
 */
export function useSettingsTabs(): {
  tabs: readonly SettingsTab[];
  activeTab: SettingsTab;
} {
  const { product } = useActiveEntitlement();
  const { isAny } = useRole();
  const stored = useAppSelector((s) => s.settings.activeTab);
  const isAdmin = isAny(ADMIN_ONLY);

  const tabs = useMemo(
    () =>
      SETTINGS_TABS.filter((tab) => {
        const requiredProduct = SETTINGS_TABS_BY_PRODUCT[tab];
        if (requiredProduct && requiredProduct !== product) return false;
        if (ADMIN_SETTINGS_TABS.includes(tab) && !isAdmin) return false;
        return true;
      }),
    [product, isAdmin],
  );

  // `tabs` always contains 'profile' — it carries no product or role condition —
  // so the fallback can never be undefined.
  return { tabs, activeTab: tabs.includes(stored) ? stored : tabs[0] };
}

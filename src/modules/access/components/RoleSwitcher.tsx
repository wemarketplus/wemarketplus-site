import { useNavigate } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import {
  CL_VIEW_AS_ROLES,
  ROLE_LABELS,
  roleTitle,
  useRole,
  type Role,
} from '@/shared/rbac';
import { Product } from '@/shared/types';
import { useActiveProduct } from '../hooks/useActiveProduct';
import { setViewAsRole } from '../store/accessSlice';

/**
 * The "Viewing As" dropdown — CommunityLink only.
 *
 * The CommunityLink guide's Getting Started, Step 3: "Look for the Viewing As
 * dropdown, usually near the top of the left menu. This is important —
 * CommunityLink actually asks which role you are and shows you a menu built just
 * for that job, unlike some CRMs where everyone sees everything." Step 4 lists the
 * options: Sales Marketer, Administrator, Executive Director, Maintenance,
 * Housekeeping, Owner/Investor, or a custom role.
 *
 * A real `<select>`, because the guide says dropdown and a user following that
 * sentence should find one — the previous version was a row of pill buttons.
 *
 * IT ONLY EVER CHANGES WHAT RENDERS. `usePermission` refuses any role that is not
 * in CL_VIEW_AS_ROLES and refuses it outright for a non-management user, and the
 * JWT is untouched — so a previewing Admin who reaches a hidden route still gets
 * that route's real authorization answer from the server. The switcher can hide a
 * screen; it can never unlock one.
 *
 * HospiceLink deliberately renders nothing here: its dashboards are not to show a
 * role-preview section. See usePermission.
 */
export function RoleSwitcher() {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { activeProduct } = useActiveProduct();
  const { actualRole, viewAsRole, canViewAs } = useRole();
  const customRole = useAppSelector((s) => s.auth.user?.customRole);

  if (!canViewAs || activeProduct !== Product.CommunityLink) return null;

  const select = (value: string) => {
    dispatch(setViewAsRole(value ? (value as Role) : null));
    /**
     * Land on the dashboard. The route the user is standing on may be one the
     * previewed persona cannot see — a Marketer has no /financial/ledger — and
     * leaving them there would render an empty shell that reads as a bug rather
     * than a scoped view. The dashboard exists for every role, and now renders
     * that role's OWN screen (see @/modules/cl-dashboard), so it is also the most
     * informative place to land.
     */
    navigate('/', { replace: true });
  };

  return (
    <div className="mt-2.5">
      <label
        htmlFor="view-as"
        className="mb-1 block text-[9px] font-bold uppercase tracking-[0.1em] text-muted-soft"
      >
        Viewing as
      </label>
      <select
        id="view-as"
        value={viewAsRole ?? ''}
        onChange={(event) => select(event.target.value)}
        className="w-full rounded-[8px] border border-border/[0.12] bg-surface px-2 py-1.5 text-[11px] font-semibold text-foreground outline-none transition-colors focus:border-primary"
      >
        {/* "Yourself" carries the custom role's name when the user holds one, so
            the control agrees with the sidebar footer and the dashboard greeting. */}
        <option value="">
          {actualRole ? roleTitle(actualRole, customRole?.name) : 'Me'}
        </option>
        {CL_VIEW_AS_ROLES.map((role) => (
          <option key={role} value={role}>
            {ROLE_LABELS[role]}
          </option>
        ))}
      </select>

      {viewAsRole && (
        <p className="mt-1.5 text-[10px] leading-snug text-warning">
          Previewing the {ROLE_LABELS[viewAsRole]} view. Your own permissions are
          unchanged — the server still answers as{' '}
          {actualRole ? ROLE_LABELS[actualRole] : 'you'}.
        </p>
      )}
    </div>
  );
}

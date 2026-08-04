import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import {
  HL_VIEW_AS_ROLES,
  ROLE_LABELS,
  useRole,
  type Role,
} from '@/shared/rbac';
import { Product } from '@/shared/types';
import { cn } from '@/shared/utils/cn';
import { useActiveProduct } from '../hooks/useActiveProduct';
import { setViewAsRole } from '../store/accessSlice';

/**
 * "Viewing as" switcher — the top build priority the module-flow document names.
 *
 * HospiceLink Gold is sold as "4-role access: Admin, Marketer, Nurse, Caregiver"
 * and shipped as a one-role product: every persona resolved to the same 42-item
 * sidebar because the HospiceLink navigation only ever used STAFF_ROLES and
 * ADMIN_ONLY. This control lets a management user see exactly what a field persona
 * sees, which is what makes the scoped views verifiable rather than theoretical.
 *
 * IT ONLY EVER NARROWS. `usePermission` resolves the effective role and refuses any
 * request that is not a field persona, so this cannot be used to view "up". And
 * because the JWT is untouched, previewing changes what renders and nothing about
 * what the server will allow — see that hook for the two invariants.
 *
 * CommunityLink already has its own role model and does not need this, so the
 * control renders only on the HospiceLink dashboard.
 */
export function RoleSwitcher() {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { activeProduct } = useActiveProduct();
  const { actualRole, viewAsRole, canViewAs } = useRole();

  if (!canViewAs || activeProduct !== Product.HospiceLink) return null;

  const select = (role: Role | null) => {
    dispatch(setViewAsRole(role));
    // Land on the dashboard: the route the user is standing on may be one the
    // previewed persona cannot see, and leaving them there would render an empty
    // shell that looks like a bug rather than a scoped view.
    navigate('/', { replace: true });
  };

  return (
    <div className="mt-2.5">
      <p className="mb-1 text-[9px] font-bold uppercase tracking-[0.1em] text-muted-soft">
        Viewing as
      </p>
      <div
        role="group"
        aria-label="Preview the app as another role"
        className="flex flex-wrap gap-1"
      >
        <button
          type="button"
          onClick={() => select(null)}
          aria-pressed={viewAsRole === null}
          className={cn(
            'rounded-[8px] px-2 py-1 text-[10px] font-bold uppercase tracking-[0.06em] transition-colors',
            viewAsRole === null
              ? 'bg-primary text-primary-foreground'
              : 'bg-foreground/[0.05] text-muted hover:text-foreground',
          )}
        >
          {actualRole ? ROLE_LABELS[actualRole] : 'Me'}
        </button>
        {HL_VIEW_AS_ROLES.map((role) => (
          <button
            key={role}
            type="button"
            onClick={() => select(role)}
            aria-pressed={viewAsRole === role}
            className={cn(
              'rounded-[8px] px-2 py-1 text-[10px] font-bold uppercase tracking-[0.06em] transition-colors',
              viewAsRole === role
                ? 'bg-primary text-primary-foreground'
                : 'bg-foreground/[0.05] text-muted hover:text-foreground',
            )}
          >
            {ROLE_LABELS[role]}
          </button>
        ))}
      </div>
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

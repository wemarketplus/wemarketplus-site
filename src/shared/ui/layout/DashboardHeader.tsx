import { LogOut } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { ProductSwitcher } from '@/modules/access';
import { logout } from '@/modules/auth';
import { NotificationsBell } from '@/modules/notifications';
import { GlobalSearch } from '@/modules/search';
import { ROLE_LABELS } from '@/shared/rbac';
import { Button } from '@/shared/ui/core/Button';

// Topbar mirrors wemarketplus-site dashboards: thin hairline divider, user
// identity + notifications on the right, no theme toggle (dark-only app).
export function DashboardHeader() {
  const dispatch = useAppDispatch();
  const user = useAppSelector((s) => s.auth.user);

  const initials = user
    ? `${user.firstName?.[0] ?? ''}${user.lastName?.[0] ?? ''}`.toUpperCase() || '?'
    : '';

  return (
    <header className="flex h-16 items-center justify-between border-b border-border/[0.06] bg-bg/80 px-6 backdrop-blur-sm">
      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-soft">
        WeMarketPlus CRM
      </div>

      <div className="flex items-center gap-2">
        <GlobalSearch />
        {/* Which dashboard is live, next to the bell. Renders nothing for
            single-product users. */}
        <ProductSwitcher />
        <NotificationsBell />
        {user && (
          <div className="flex items-center gap-3 rounded-pill border border-border/[0.08] bg-surface/60 py-1 pr-3 pl-1">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/20 text-[11px] font-semibold text-primary">
              {initials}
            </div>
            <div className="hidden text-right sm:block">
              <p className="text-xs font-semibold text-foreground leading-none">
                {user.firstName} {user.lastName}
              </p>
              <p className="mt-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft leading-none">
                {ROLE_LABELS[user.role]}
              </p>
            </div>
          </div>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => dispatch(logout())}
          aria-label="Sign out"
        >
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Sign out</span>
        </Button>
      </div>
    </header>
  );
}

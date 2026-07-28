import { NavLink } from 'react-router-dom';
import { OWNER_NAV } from '../constants/ownerNavConstants';
import { Logo } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';

export function OwnerSidebar() {
  return (
    <aside className="hidden h-full w-[240px] shrink-0 flex-col border-r border-border/[0.06] bg-ink/95 md:flex">
      <div className="flex h-16 items-center px-5 border-b border-border/[0.06]">
        <Logo size="sm" />
      </div>
      <div className="px-5 py-3 border-b border-border/[0.06]">
        <p className="text-[10px] uppercase tracking-[0.16em] text-muted-soft">
          Owner portal
        </p>
        <p className="mt-0.5 text-sm font-semibold text-foreground">
          Private command center
        </p>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto p-3" aria-label="Owner sections">
        {OWNER_NAV.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/owner'}
              className={({ isActive }) =>
                cn(
                  'group flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] font-medium transition-colors',
                  isActive
                    ? 'bg-primary/15 text-primary'
                    : 'text-muted hover:bg-foreground/[0.04] hover:text-foreground',
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    className={cn(
                      'h-4 w-4 shrink-0 transition-colors',
                      isActive ? 'text-primary' : 'text-muted-soft group-hover:text-foreground',
                    )}
                  />
                  <span className="truncate">{item.label}</span>
                  {item.badge && (
                    <span className="ml-auto rounded-pill bg-warning/15 px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-warning">
                      {item.badge}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
}

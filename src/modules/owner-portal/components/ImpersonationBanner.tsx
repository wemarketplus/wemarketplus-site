import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogOut, UserCog } from 'lucide-react';
import { useImpersonation } from '../hooks/useImpersonation';
import {
  readActiveImpersonation,
  type ActiveImpersonation,
} from '../utils/impersonationSession';

/**
 * Persistent banner shown while a SuperAdmin is impersonating a tenant. Reads
 * the active impersonation marker from localStorage (set at start), so it shows
 * across reloads and the hard navigation into the workspace. "Exit" ends the
 * session (audit + restore operator) and returns to the owner customers screen.
 */
export function ImpersonationBanner() {
  const { stop, isStopping } = useImpersonation();
  const navigate = useNavigate();
  const [active, setActive] = useState<ActiveImpersonation | null>(null);

  useEffect(() => {
    setActive(readActiveImpersonation());
  }, []);

  if (!active) {
    return null;
  }

  const onExit = async () => {
    await stop();
    setActive(null);
    navigate('/owner/customers');
  };

  return (
    <div className="flex items-center justify-between gap-3 bg-amber-500/15 px-[22px] py-2 text-sm text-amber-100 ring-1 ring-inset ring-amber-500/30">
      <span className="flex items-center gap-2">
        <UserCog className="h-4 w-4 shrink-0" />
        You are impersonating{' '}
        <strong className="font-semibold">{active.organizationName}</strong>
      </span>
      <button
        type="button"
        onClick={onExit}
        disabled={isStopping}
        className="inline-flex items-center gap-1.5 rounded-pill border border-amber-400/40 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-amber-100 transition-colors hover:border-amber-300 hover:text-white disabled:opacity-50"
      >
        <LogOut className="h-3.5 w-3.5" />
        {isStopping ? 'Exiting…' : 'Exit'}
      </button>
    </div>
  );
}

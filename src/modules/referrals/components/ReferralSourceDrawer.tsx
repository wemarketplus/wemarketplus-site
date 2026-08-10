import { CalendarPlus, MessageSquarePlus } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { Pill, StatTile } from '@/shared/ui/data-display';
import { TouchLog } from '@/modules/activity';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  REFERRAL_ACCOUNT_STATUS_LABELS,
} from '../constants/referralsConstants';
import type { ReferralSourceRecord } from '../types/referralsTypes';
import type { NoteRecord } from '@/modules/activity/types/activityTypes';

interface ReferralSourceDrawerProps {
  /** Visibility, from explicit state — never derived from `source`. See
   *  ProspectDrawer for why a data-derived condition could not close. */
  open: boolean;
  source: ReferralSourceRecord | undefined;
  notes: readonly NoteRecord[];
  isLoading: boolean;
  isNotesLoading: boolean;
  onClose: () => void;
  onLogInteraction: () => void;
  onScheduleVisit: () => void;
}

const line = (parts: Array<string | null | undefined>) =>
  parts.filter(Boolean).join(', ') || '—';

/**
 * Everything a marketer needs about one account, in one place: how to reach it,
 * how much it has referred, when it was last actually touched, and the full
 * interaction history — plus the two actions they take from here.
 *
 * The two actions matter as much as the data. Requiring a marketer to leave this
 * record, open Notes, and re-find the facility by name to log a drop-off is how
 * touch logs stop being filled in.
 */
export function ReferralSourceDrawer({
  open,
  source,
  notes,
  isLoading,
  isNotesLoading,
  onClose,
  onLogInteraction,
  onScheduleVisit,
}: ReferralSourceDrawerProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title={source?.name ?? 'Referral source'}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button variant="ghost" onClick={onScheduleVisit} disabled={!source}>
            <CalendarPlus className="h-4 w-4" /> Schedule visit
          </Button>
          <Button onClick={onLogInteraction} disabled={!source}>
            <MessageSquarePlus className="h-4 w-4" /> Touch log
          </Button>
        </>
      }
    >
      {!source ? (
        // Open with no record yet is either a fetch in flight or one that
        // failed. Saying which is the difference between "wait a moment" and
        // "close this and try again" — a permanent "Loading…" is a lie.
        <p className="py-6 text-sm text-muted">
          {isLoading
            ? 'Loading account…'
            : 'We could not load this account. Please close and try again.'}
        </p>
      ) : (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2">
            <Pill tone="b">
              {REFERRAL_ACCOUNT_STATUS_LABELS[source.status]}
            </Pill>
            <Pill tone="p">Tier {source.priorityTier}</Pill>
            {source.isCold && <Pill tone="r">Cold</Pill>}
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <StatTile
              label="Referrals"
              value={String(source.referralVolume)}
              tone="g"
            />
            <StatTile
              label="Last interaction"
              // Never-touched is spelled out. A dash here would read as "no data
              // available" rather than "nobody has ever been".
              value={
                source.lastInteractionAt
                  ? formatDate(source.lastInteractionAt)
                  : 'Never'
              }
              hint={
                source.daysSinceLastInteraction === null
                  ? 'No visit or call logged'
                  : `${source.daysSinceLastInteraction} days ago`
              }
              tone={source.isCold ? 'r' : 'b'}
            />
            <StatTile
              label="Score"
              value={String(source.aiScore)}
              hint="Hand-set 1–10"
              tone="y"
            />
          </div>

          <section className="space-y-1.5">
            <h3 className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
              Contact
            </h3>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
              <div className="flex gap-2">
                <dt className="text-muted">Contact</dt>
                <dd className="text-foreground">{source.contactName ?? '—'}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-muted">Phone</dt>
                <dd className="text-foreground">{source.phone ?? '—'}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-muted">Email</dt>
                <dd className="text-foreground">{source.email ?? '—'}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-muted">Fax</dt>
                <dd className="text-foreground">{source.fax ?? '—'}</dd>
              </div>
              <div className="flex gap-2 sm:col-span-2">
                <dt className="text-muted">Address</dt>
                <dd className="text-foreground">
                  {line([
                    source.address,
                    source.city,
                    source.state,
                    source.zip,
                  ])}
                </dd>
              </div>
            </dl>
          </section>

          <section className="space-y-1.5">
            <h3 className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
              Interaction history
            </h3>
            <TouchLog
              notes={notes}
              isLoading={isNotesLoading}
              emptyLabel="No visits or calls logged against this account yet."
            />
          </section>
        </div>
      )}
    </Modal>
  );
}

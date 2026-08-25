import { PAGE_TITLE, SECTION_TITLE } from '@/shared/ui/core/typography';
import { useMemo } from 'react';
import { Map as MapIcon } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill, StatTile } from '@/shared/ui/data-display';
import { useListReferralsQuery } from '@/modules/referrals';
import type { ReferralSourceRecord } from '@/modules/referrals';
import { LOOKUP_PAGE_SIZE } from '@/shared/hooks/useRecordLookups';
import { useListTerritoriesQuery } from '../api/territoriesApi';
import { TERRITORY_PRIORITY_LABELS } from '../constants/territoriesConstants';

/**
 * Accounts are fetched in one page; territories are a planning view, not a feed.
 * Capped at the backend's MAX_LIMIT — asking for more is a 400, not a bigger
 * page, which would leave this screen silently empty.
 */
const ACCOUNT_LIMIT = LOOKUP_PAGE_SIZE;

interface TerritoryGroup {
  id: string;
  name: string;
  area: string;
  priority: string;
  accounts: ReferralSourceRecord[];
  coldCount: number;
}

/**
 * The territory planning view: which accounts sit in which patch, and which of
 * them are going cold.
 *
 * Deliberately NOT a map. `territories` stores a name, a city/state and a list of
 * ZIP codes — there are no coordinates on either table, so a map would mean
 * geocoding every account, a tile provider, and a key to manage. What a marketer
 * planning a day actually needs is "which accounts are in this area and which
 * ones am I overdue on", and that is answerable from the data that exists.
 *
 * Grouping is done client-side over one page of accounts because the join is
 * `referral_sources.territoryId` and both lists are small (a tenant has a handful
 * of territories and hundreds of accounts at most). If either grows past that, a
 * server-side group-by belongs in the referral-sources module, not here.
 */
export function TerritoryPlannerPage() {
  const { data: territories, isLoading: territoriesLoading } =
    useListTerritoriesQuery();
  const { data: accounts, isLoading: accountsLoading } = useListReferralsQuery({
    limit: ACCOUNT_LIMIT,
  });

  const { groups, unassigned } = useMemo(() => {
    const rows = accounts?.data ?? [];
    const byTerritory = new Map<string, ReferralSourceRecord[]>();
    const orphans: ReferralSourceRecord[] = [];

    for (const account of rows) {
      if (!account.territoryId) {
        orphans.push(account);
        continue;
      }
      const bucket = byTerritory.get(account.territoryId) ?? [];
      bucket.push(account);
      byTerritory.set(account.territoryId, bucket);
    }

    const built: TerritoryGroup[] = (territories?.data ?? []).map((t) => {
      const members = byTerritory.get(t.id) ?? [];
      return {
        id: t.id,
        name: t.name,
        area: [t.city, t.state].filter(Boolean).join(', '),
        priority: TERRITORY_PRIORITY_LABELS[t.priority] ?? t.priority,
        accounts: members,
        // `isCold` is the server's answer against the 14-day rule, never
        // recomputed here.
        coldCount: members.filter((a) => a.isCold).length,
      };
    });

    // Most-neglected territory first: the planner exists to decide where to
    // drive today, and a list sorted by name buries the answer.
    built.sort((a, b) => b.coldCount - a.coldCount || a.name.localeCompare(b.name));

    return { groups: built, unassigned: orphans };
  }, [territories, accounts]);

  const isLoading = territoriesLoading || accountsLoading;

  const totalAccounts = groups.reduce((n, g) => n + g.accounts.length, 0);
  const totalCold = groups.reduce((n, g) => n + g.coldCount, 0);

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>
          Territory planner
        </h1>
        <p className="text-sm text-muted">
          Where your accounts are, and which ones are overdue a visit.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatTile
          label="Territories"
          value={String(groups.length)}
          tone="b"
          icon={MapIcon}
        />
        <StatTile label="Accounts placed" value={String(totalAccounts)} tone="g" />
        <StatTile
          label="Going cold"
          value={String(totalCold)}
          tone={totalCold > 0 ? 'r' : 'g'}
        />
        <StatTile
          label="Unassigned"
          value={String(unassigned.length)}
          hint="No territory set"
          tone="y"
        />
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading territories…
          </CardContent>
        </Card>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            No territories defined yet. Create them under Territories, then set a
            territory on each referral source to see them grouped here.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {groups.map((group) => (
            <Card key={group.id}>
              <CardContent className="px-0 pb-0 pt-0">
                <header className="flex flex-wrap items-center gap-3 px-6 py-4">
                  <div className="min-w-0 flex-1">
                    <h2 className={SECTION_TITLE}>
                      {group.name}
                    </h2>
                    <p className="text-[11px] text-muted-soft">
                      {group.area || 'No area set'} · {group.priority} priority
                    </p>
                  </div>
                  <Pill tone="b">{group.accounts.length} accounts</Pill>
                  {group.coldCount > 0 && (
                    <Pill tone="r">{group.coldCount} cold</Pill>
                  )}
                </header>

                {group.accounts.length === 0 ? (
                  <p className="px-6 pb-5 text-xs text-muted-soft">
                    No accounts assigned to this territory.
                  </p>
                ) : (
                  <ul className="divide-y divide-border border-t border-border">
                    {/* Cold accounts float to the top of each territory — this
                        list is a driving order, not an index. */}
                    {[...group.accounts]
                      .sort(
                        (a, b) =>
                          Number(b.isCold) - Number(a.isCold) ||
                          a.name.localeCompare(b.name),
                      )
                      .map((account) => (
                        <li
                          key={account.id}
                          className="flex flex-wrap items-center gap-3 px-6 py-2.5"
                        >
                          <div className="min-w-0 flex-1">
                            <p className="text-sm text-foreground">
                              {account.name}
                            </p>
                            <p className="text-[11px] text-muted-soft">
                              {[account.city, account.state]
                                .filter(Boolean)
                                .join(', ') || 'No address'}
                              {' · '}
                              {account.lastInteractionAt
                                ? `${account.daysSinceLastInteraction}d since last touch`
                                : 'never contacted'}
                            </p>
                          </div>
                          <span className="text-[11px] tabular-nums text-muted">
                            {account.referralCount} referrals
                          </span>
                          {account.isCold && <Pill tone="r">Cold</Pill>}
                        </li>
                      ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {unassigned.length > 0 && (
        <Card>
          <CardContent className="space-y-2 px-6 py-5">
            <h2 className={SECTION_TITLE}>
              Not in a territory
            </h2>
            {/* Surfaced rather than hidden: an unassigned account is invisible to
                territory planning and to the daily queue's owner-scoped cold
                list, so it can go untouched indefinitely without anyone noticing. */}
            <p className="text-[11px] text-muted-soft">
              These accounts will not appear in any territory plan. Set a
              territory on each from Referral sources.
            </p>
            <ul className="flex flex-wrap gap-2 pt-1">
              {unassigned.map((account) => (
                <li key={account.id}>
                  <Pill tone={account.isCold ? 'r' : 'b'}>{account.name}</Pill>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

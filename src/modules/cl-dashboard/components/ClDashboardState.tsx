import { Card, CardContent } from '@/shared/ui/core';

/**
 * The loading / failed states every CommunityLink dashboard variant shares.
 *
 * One component rather than the same two ternaries in four files: a dashboard
 * that silently renders zeroes when its request failed is worse than one that
 * says it could not load, and four copies of that guard is four chances to omit
 * it. Zeroes on this screen read as "you have no leads", which is a very
 * different message from "we could not reach the server".
 */
export function ClDashboardState({ isError }: { isError: boolean }) {
  return (
    <Card>
      <CardContent className="px-6 py-8 text-sm text-muted">
        {isError
          ? 'We could not load your dashboard right now. Please try again in a moment.'
          : 'Loading your dashboard…'}
      </CardContent>
    </Card>
  );
}

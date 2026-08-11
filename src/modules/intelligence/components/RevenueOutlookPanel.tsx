import { Link } from 'react-router-dom';
import { StatTile } from '@/shared/ui/data-display';
import type { RevenueOutlook } from '../types/intelligenceTypes';

/**
 * Every money figure here keeps its cents. Mileage cost feeds cost-per-admission,
 * so rounding $10.52 to "$11" on the tile while the division uses 10.52 makes the
 * arithmetic on screen fail to add up.
 */
const currency = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});
const decimal = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });

/** Rendered where a figure genuinely cannot be computed, never a zero. */
const UNAVAILABLE = '—';

/**
 * Cost per admission and forecasted admissions.
 *
 * The honesty rules this panel exists to hold:
 *
 *  - A null cost renders as "—" with an explanation and a link to record spend.
 *    Showing 0 would tell a director their marketing is free.
 *  - The forecast shows BOTH halves of its blend (run-rate and pipeline), because
 *    the disagreement between them is the informative part — a pipeline estimate
 *    well below run-rate means the funnel is drying up.
 */
export function RevenueOutlookPanel({ outlook }: { outlook: RevenueOutlook }) {
  const hasCost = outlook.totalCost !== null;
  const hasForecast = outlook.forecastedAdmits !== null;

  const costHint = (): string => {
    if (outlook.costPerAdmission !== null) {
      return `${currency.format(outlook.totalCost ?? 0)} total cost ÷ ${outlook.admits} admission${
        outlook.admits === 1 ? '' : 's'
      }`;
    }
    if (!hasCost) {
      return 'No marketing spend recorded yet.';
    }
    return 'No admissions in this window to divide by.';
  };

  return (
    <section className="space-y-3">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Cost per admission"
          value={
            outlook.costPerAdmission === null
              ? UNAVAILABLE
              : currency.format(outlook.costPerAdmission)
          }
          hint={costHint()}
          tone="gd"
        />
        <StatTile
          label="Marketing spend"
          value={
            outlook.marketingSpend === null
              ? UNAVAILABLE
              : currency.format(outlook.marketingSpend)
          }
          hint={
            outlook.marketingSpend === null
              ? 'Set a monthly figure in financial settings.'
              : 'Your monthly figure, pro-rated across this window.'
          }
          tone="b"
        />
        <StatTile
          label="Mileage cost"
          value={currency.format(outlook.mileageCost)}
          hint="Reimbursement paid on trips filed in this window."
          tone="b"
        />
        <StatTile
          label={`Forecast admits (${outlook.forecastHorizonDays}d)`}
          value={
            hasForecast ? decimal.format(outlook.forecastedAdmits ?? 0) : UNAVAILABLE
          }
          hint={
            hasForecast
              ? `Run-rate ${decimal.format(outlook.forecastRunRate ?? 0)} · pipeline ${decimal.format(
                  outlook.forecastPipeline ?? 0,
                )} (${outlook.openPipelineCount} open)`
              : 'Window is too short to project from.'
          }
          tone="g"
        />
      </div>

      {!hasCost && (
        <p className="text-xs text-muted">
          Cost per admission needs a monthly marketing spend figure.{' '}
          <Link
            to="/financial-settings"
            className="font-semibold text-primary underline-offset-2 hover:underline"
          >
            Record it in financial settings
          </Link>{' '}
          and this fills in. Mileage reimbursement is already counted
          automatically.
        </p>
      )}
    </section>
  );
}

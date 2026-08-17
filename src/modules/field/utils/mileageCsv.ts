import type { MileageLogRecord } from '../types/fieldTypes';

const HEADERS = [
  'Date',
  'From',
  'To',
  'Purpose',
  'Miles',
  'Rate',
  'Reimbursement',
] as const;

/**
 * Quote one cell and escape any embedded quotes.
 *
 * Every cell is quoted unconditionally rather than only when it contains a comma:
 * `purpose` is free text a field worker types, so it routinely holds commas and
 * quotation marks, and a rule that only sometimes quotes is a rule that eventually
 * shifts a column. Mirrors the same treatment in the CommunityLink reports export
 * (wemarketplus-backend cl-reports.controller.ts).
 */
const cell = (value: string | number | null): string =>
  `"${String(value ?? '').replace(/"/g, '""')}"`;

/**
 * Mileage trips as a CSV string — pure, so it is testable without a DOM. The
 * download itself is `useCsvDownload` (shared/hooks).
 *
 * Numbers are emitted UNFORMATTED (no `$`, no thousands separators): this file is
 * opened in a spreadsheet to be totalled, and a currency-formatted string lands as
 * text that will not sum. The screen keeps the formatted view; the export keeps
 * the arithmetic.
 *
 * `reimbursementAmount` is null on rows saved before a rate existed — emitted as
 * an empty cell, not 0, because a blank reads as "not calculated" while a zero
 * reads as "no reimbursement owed".
 */
export function mileageLogsToCsv(rows: readonly MileageLogRecord[]): string {
  const lines = [HEADERS.map(cell).join(',')];
  for (const row of rows) {
    lines.push(
      [
        cell(row.date),
        cell(row.fromLocation),
        cell(row.toLocation),
        cell(row.purpose),
        cell(Number(row.miles).toFixed(1)),
        cell(Number(row.reimbursementRate)),
        cell(
          row.reimbursementAmount === null
            ? ''
            : Number(row.reimbursementAmount).toFixed(2),
        ),
      ].join(','),
    );
  }
  // CRLF: Excel is the destination for most of these and it is the line ending
  // RFC 4180 specifies.
  return lines.join('\r\n');
}

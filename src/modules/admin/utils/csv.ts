// Minimal RFC-4180-ish CSV parser used by the Data Import screen. The backend
// import endpoints (data-transfer.controller POST /import/:type) accept parsed
// JSON `rows` keyed by header, NOT raw CSV text — so the browser parses the
// uploaded file into row objects before posting.

/** Parse CSV text into an array of cell-arrays. Handles quoted fields, escaped
 *  double-quotes ("") and CRLF/LF line endings. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let field = '';
  let row: string[] = [];
  let inQuotes = false;

  // Strip a leading UTF-8 BOM if present.
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;

  for (let i = 0; i < src.length; i += 1) {
    const char = src[i];

    if (inQuotes) {
      if (char === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      inQuotes = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (char === '\r') {
      // Swallow CR; the following LF (if any) ends the row.
    } else {
      field += char;
    }
  }

  // Flush the trailing field/row (files without a final newline).
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows;
}

/** Parse CSV text into header-keyed row objects, skipping fully-blank lines. */
export function parseCsvToRows(text: string): Record<string, string>[] {
  const matrix = parseCsv(text);
  if (matrix.length === 0) return [];

  const headers = matrix[0].map((h) => h.trim());
  const rows: Record<string, string>[] = [];

  for (let i = 1; i < matrix.length; i += 1) {
    const cells = matrix[i];
    // Skip empty trailing lines.
    if (cells.length === 1 && cells[0].trim() === '') continue;

    const record: Record<string, string> = {};
    headers.forEach((header, col) => {
      if (header) record[header] = (cells[col] ?? '').trim();
    });
    rows.push(record);
  }

  return rows;
}

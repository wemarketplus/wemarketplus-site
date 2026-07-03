import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useImportDataMutation } from '../api/adminApi';
import { parseCsvToRows } from '../utils/csv';
import type { ImportResult } from '../types/adminTypes';

interface ImportState {
  fileName: string | null;
  rowCount: number;
  result: ImportResult | null;
  errorMessage: string | null;
}

const EMPTY: ImportState = {
  fileName: null,
  rowCount: 0,
  result: null,
  errorMessage: null,
};

// Drives the CSV-upload → parse → POST /import/:type flow. Parsing happens in
// the browser because the backend expects JSON `rows`, not raw CSV.
export function useDataImport() {
  const [importData, { isLoading }] = useImportDataMutation();
  const [rows, setRows] = useState<Record<string, string>[]>([]);
  const [state, setState] = useState<ImportState>(EMPTY);

  const reset = useCallback(() => {
    setRows([]);
    setState(EMPTY);
  }, []);

  const loadFile = useCallback(async (file: File) => {
    try {
      const text = await file.text();
      const parsed = parseCsvToRows(text);
      setRows(parsed);
      setState({
        fileName: file.name,
        rowCount: parsed.length,
        result: null,
        errorMessage:
          parsed.length === 0 ? 'No data rows found in this file.' : null,
      });
    } catch {
      setRows([]);
      setState({
        ...EMPTY,
        fileName: file.name,
        errorMessage: 'Could not read this file. Upload a UTF-8 CSV.',
      });
    }
  }, []);

  const runImport = useCallback(
    async (type: string) => {
      if (rows.length === 0) return;
      try {
        const result = await importData({ type, rows }).unwrap();
        setState((prev) => ({ ...prev, result, errorMessage: null }));
        if (result.errors.length > 0) {
          toast.warning(
            `Imported ${result.created} row(s) with ${result.errors.length} error(s).`,
          );
        } else {
          toast.success(`Imported ${result.created} row(s).`);
        }
      } catch (err) {
        const message = extractApiErrorMessage(err, 'Import failed.');
        setState((prev) => ({ ...prev, result: null, errorMessage: message }));
        toast.error(message);
      }
    },
    [importData, rows],
  );

  return {
    ...state,
    hasRows: rows.length > 0,
    isImporting: isLoading,
    loadFile,
    runImport,
    reset,
  };
}

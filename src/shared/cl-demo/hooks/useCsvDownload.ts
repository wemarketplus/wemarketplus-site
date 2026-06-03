// Side-effecting CSV download (Blob + anchor click) — the runtime counterpart
// to the pure CSV string builders in each demo module's utils. Kept in a hook
// because it touches the DOM/URL APIs.
import { useCallback } from 'react';

export function useCsvDownload() {
  return useCallback((csv: string, filenamePrefix: string) => {
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filenamePrefix}-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);
}

// Side-effecting CSV download (Blob + anchor click) — the runtime counterpart to
// the pure CSV string builders each module keeps in its own utils/.
//
// Lives here rather than in shared/cl-demo, where it started: it is now used by a
// production screen (modules/field's mileage export) as well as by the three demo
// modules, and shared/cl-demo is the DEMO design system — production code has no
// business importing from it. shared/cl-demo/index.ts re-exports this so no demo
// call site had to change.
//
// Kept as a hook rather than a plain function because it touches the DOM/URL APIs.
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

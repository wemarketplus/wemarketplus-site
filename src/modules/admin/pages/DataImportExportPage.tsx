import { PAGE_TITLE, SECTION_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useRef, useState } from 'react';
import { Download, FileSpreadsheet, Upload } from 'lucide-react';
import { toast } from 'sonner';
import { useAppSelector } from '@/app/hooks';
import { useActiveEntitlement } from '@/modules/access';
import { Button, Card, CardContent, Select } from '@/shared/ui/core';
import { Alert } from '@/shared/ui/data-display';
import { useDataImport } from '../hooks/useDataImport';
import { downloadAuthenticated } from '../utils/authenticatedDownload';
import {
  exportCsvUrl,
  exportXlsxUrl,
  importTemplateCsvUrl,
  importTemplateXlsxUrl,
} from '../utils/dataTransferUrls';
import { datasetOptionsForProduct } from '../types/adminTypes';

// Data Import / Export — wired to the wemarketplus-backend data-transfer hub
// (GET /export/:type[/xlsx], GET /template/:type, GET /import/template/:type/xlsx,
// POST /import/:type). Every route is guarded by @RequirePermission('import_export');
// downloads and the import call surface 401/403 to the user.
export function DataImportExportPage() {
  const token = useAppSelector((s) => s.auth?.token ?? null);
  // The hub is a shared screen; the dataset list is scoped to the dashboard in
  // use so a CommunityLink tenant is never offered HospiceLink's prospects.
  const { product } = useActiveEntitlement();
  const datasetOptions = useMemo(
    () => datasetOptionsForProduct(product),
    [product],
  );
  const [type, setType] = useState(datasetOptions[0].type);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const dataset = useMemo(
    // Falls back to the first option when the selected type is not available for
    // this product — which happens if the user switches dashboards while the
    // page is open.
    () => datasetOptions.find((d) => d.type === type) ?? datasetOptions[0],
    [datasetOptions, type],
  );

  const {
    fileName,
    rowCount,
    result,
    errorMessage,
    hasRows,
    isImporting,
    loadFile,
    runImport,
    reset,
  } = useDataImport();

  const download = async (action: string, url: string) => {
    setBusyAction(action);
    const status = await downloadAuthenticated(url, token);
    setBusyAction(null);
    if (status === 403) {
      toast.error('You do not have permission to export or download templates.');
    } else if (status === 401) {
      toast.error('Your session has expired. Sign in again.');
    } else if (status === 0 || status >= 400) {
      toast.error('Download failed. Try again.');
    }
  };

  const onPickFile = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) void loadFile(file);
    // Allow re-selecting the same filename to re-trigger onChange.
    event.target.value = '';
  };

  const onSelectType = (value: string) => {
    setType(value);
    reset();
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1">
        <h1 className={PAGE_TITLE}>Data import and export</h1>
        <p className="text-sm text-muted">
          Download a template, export your records, or bulk import from a CSV.
        </p>
      </header>

      <Card>
        <CardContent className="space-y-5 pt-6">
          <div className="max-w-sm space-y-1.5">
            <label
              htmlFor="dataset-type"
              className="text-[11px] font-semibold uppercase tracking-label text-muted-soft"
            >
              Entity type
            </label>
            <Select
              id="dataset-type"
              value={type}
              onChange={(e) => onSelectType(e.target.value)}
            >
              {datasetOptions.map((option) => (
                <option key={option.type} value={option.type}>
                  {option.label}
                </option>
              ))}
            </Select>
            {dataset.elevated && (
              <p className="text-[11px] text-muted-soft">
                Exporting {dataset.label.toLowerCase()} requires an elevated role.
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* --- Export ------------------------------------------------------- */}
        <Card>
          <CardContent className="space-y-4 pt-6">
            <div className="flex items-center gap-2">
              <Download className="h-4 w-4 text-primary" />
              <h2 className={SECTION_TITLE}>Export records</h2>
            </div>
            <p className="text-sm text-muted">
              Download every {dataset.label.toLowerCase()} record in your workspace.
            </p>
            <div className="flex flex-wrap gap-3">
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction !== null}
                onClick={() => download('export-csv', exportCsvUrl(type))}
              >
                {busyAction === 'export-csv' ? 'Preparing…' : 'Export CSV'}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyAction !== null}
                onClick={() => download('export-xlsx', exportXlsxUrl(type))}
              >
                <FileSpreadsheet className="h-4 w-4" />
                {busyAction === 'export-xlsx' ? 'Preparing…' : 'Export XLSX'}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* --- Template ----------------------------------------------------- */}
        <Card>
          <CardContent className="space-y-4 pt-6">
            <div className="flex items-center gap-2">
              <FileSpreadsheet className="h-4 w-4 text-primary" />
              <h2 className={SECTION_TITLE}>Import template</h2>
            </div>
            {dataset.canImport ? (
              <>
                <p className="text-sm text-muted">
                  Download the column template, fill it in, then upload it below.
                </p>
                <div className="flex flex-wrap gap-3">
                  <Button
                    variant="secondary"
                    size="sm"
                    disabled={busyAction !== null}
                    onClick={() =>
                      download('template-csv', importTemplateCsvUrl(type))
                    }
                  >
                    {busyAction === 'template-csv' ? 'Preparing…' : 'Template CSV'}
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    disabled={busyAction !== null}
                    onClick={() =>
                      download('template-xlsx', importTemplateXlsxUrl(type))
                    }
                  >
                    <FileSpreadsheet className="h-4 w-4" />
                    {busyAction === 'template-xlsx' ? 'Preparing…' : 'Template XLSX'}
                  </Button>
                </div>
              </>
            ) : (
              <Alert tone="y">
                {dataset.label} is export only. There is no import template for this
                entity.
              </Alert>
            )}
          </CardContent>
        </Card>
      </div>

      {/* --- Import ---------------------------------------------------------- */}
      {dataset.canImport && (
        <Card>
          <CardContent className="space-y-4 pt-6">
            <div className="flex items-center gap-2">
              <Upload className="h-4 w-4 text-primary" />
              <h2 className={SECTION_TITLE}>
                Import {dataset.label.toLowerCase()} from CSV
              </h2>
            </div>
            <p className="text-sm text-muted">
              Upload a CSV that matches the template. Rows are parsed in your browser
              and sent for validation. Rows missing required fields are skipped and
              reported.
            </p>

            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,text/csv"
              onChange={onPickFile}
              className="block w-full max-w-md text-sm text-muted file:mr-4 file:rounded-pill file:border-0 file:bg-surface-raised file:px-4 file:py-2 file:text-sm file:font-semibold file:text-foreground hover:file:opacity-80"
            />

            {fileName && (
              <p className="text-sm text-muted">
                <span className="font-semibold text-foreground">{fileName}</span>
                {rowCount > 0 && ` — ${rowCount} row${rowCount === 1 ? '' : 's'} ready`}
              </p>
            )}

            {errorMessage && <Alert tone="r">{errorMessage}</Alert>}

            <div className="flex gap-3">
              <Button
                size="sm"
                disabled={!hasRows || isImporting}
                onClick={() => runImport(type)}
              >
                {isImporting ? 'Importing…' : `Import ${rowCount || ''} rows`.trim()}
              </Button>
              {(fileName || result) && (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={isImporting}
                  onClick={() => {
                    reset();
                    if (fileInputRef.current) fileInputRef.current.value = '';
                  }}
                >
                  Clear
                </Button>
              )}
            </div>

            {result && (
              <div className="space-y-3">
                <Alert tone={result.errors.length > 0 ? 'y' : 'g'}>
                  Imported {result.created} row{result.created === 1 ? '' : 's'}
                  {result.errors.length > 0
                    ? ` with ${result.errors.length} error${
                        result.errors.length === 1 ? '' : 's'
                      }.`
                    : '.'}
                </Alert>
                {result.errors.length > 0 && (
                  <div className="rounded-md border border-border/[0.08] bg-surface p-3">
                    <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-label text-muted-soft">
                      Skipped rows
                    </p>
                    <ul className="max-h-48 space-y-1 overflow-y-auto text-[13px] text-muted">
                      {result.errors.map((error, i) => (
                        <li key={i}>{error}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

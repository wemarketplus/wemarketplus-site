import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { useState } from 'react';
import { DownloadCloud, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import { useAppSelector } from '@/app/hooks';
import { downloadAuthenticated } from '@/modules/admin/utils/authenticatedDownload';
import { Role, useRole } from '@/shared/rbac';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { Alert } from '@/shared/ui/data-display';
import { dataExportDownloadUrl } from '../utils/dataExportUrl';

// Roles allowed to export the whole organization's data (mirrors the backend
// @Roles(Admin, Owner) on GET /data-export; SuperAdmin passes implicitly).
const EXPORT_ROLES: readonly Role[] = [Role.SuperAdmin, Role.Admin, Role.Owner];

// What the DSAR bundle contains — kept in sync with DataExportService on the
// backend. Shown to the user so they know what they are downloading.
const INCLUDED = [
  'Organization profile',
  'Team members (no passwords or password hashes)',
  'Contacts',
  'Companies',
  'Prospects',
  'Invoices',
  'A recent sample of the audit log',
];

export function DataExportTab() {
  const { isAny } = useRole();
  const token = useAppSelector((s) => s.auth?.token ?? null);
  const [isDownloading, setIsDownloading] = useState(false);
  const canExport = isAny(EXPORT_ROLES);

  const onDownload = async () => {
    setIsDownloading(true);
    const status = await downloadAuthenticated(dataExportDownloadUrl(), token);
    setIsDownloading(false);
    if (status === 403) {
      toast.error('Only an administrator or owner can export organization data.');
    } else if (status === 401) {
      toast.error('Your session has expired. Sign in again.');
    } else if (status === 0 || status >= 400) {
      toast.error('Export failed. Try again.');
    } else {
      toast.success('Your data export is downloading.');
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="space-y-5 px-6 py-5">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
              <DownloadCloud className="h-4 w-4" />
            </div>
            <div>
              <h2 className={SECTION_TITLE}>
                Export your organization's data
              </h2>
              <p className="mt-1 text-sm text-muted">
                Download a machine readable JSON archive of your organization's core
                records for portability (GDPR / DSAR). This is a copy of your data; nothing
                is deleted.
              </p>
            </div>
          </div>

          <div className="rounded-md border border-border/[0.08] bg-surface p-4">
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-label text-muted-soft">
              What's included
            </p>
            <ul className="grid grid-cols-1 gap-1.5 text-sm text-muted sm:grid-cols-2">
              {INCLUDED.map((item) => (
                <li key={item} className="flex items-center gap-2">
                  <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-primary/70" />
                  {item}
                </li>
              ))}
            </ul>
            <p className="mt-3 text-[12px] text-muted-soft">
              Large tables are capped per collection; a truncated section reports its full
              total in the file. Passwords and payment provider secrets are never included.
            </p>
          </div>

          {canExport ? (
            <div className="flex flex-wrap items-center gap-3">
              <Button disabled={isDownloading} onClick={() => void onDownload()}>
                <DownloadCloud className="h-4 w-4" />
                {isDownloading ? 'Preparing…' : "Download my organization's data"}
              </Button>
              <span className="text-[12px] text-muted-soft">JSON format</span>
            </div>
          ) : (
            <Alert tone="y">
              Only an administrator or owner can export the organization's data. Contact an
              admin if you need a copy.
            </Alert>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

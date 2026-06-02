import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Button, Card, CardContent, Input, Label } from '@/shared/ui/core';
import { PortalShell } from '../components/PortalShell';
import { useEvidenceExport } from '../hooks/useEvidenceExport';

export function EvidenceExportPage() {
  const { onExportJson, onExportCsv } = useEvidenceExport();
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');

  return (
    <PortalShell
      title="Audit Evidence Export"
      description="Download HIPAA audit evidence for regulatory audits. Include in your compliance documentation."
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card dense>
          <CardContent className="space-y-4 px-6 py-6">
            <h2 className="text-base font-semibold text-foreground">Export Audit Package</h2>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="start">Start Date</Label>
                <Input id="start" type="date" value={start} onChange={(e) => setStart(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="end">End Date</Label>
                <Input id="end" type="date" value={end} onChange={(e) => setEnd(e.target.value)} />
              </div>
            </div>
            <div className="flex gap-2">
              <Button onClick={onExportJson}>
                📤 Export JSON Package
              </Button>
              <Button variant="secondary" onClick={onExportCsv}>
                📊 Export CSV
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card dense>
          <CardContent className="space-y-3 px-6 py-6">
            <h2 className="text-base font-semibold text-foreground">
              HIPAA Readiness Score History
            </h2>
            <p className="text-sm text-muted">
              Run the readiness score monthly and save the output as audit evidence.
            </p>
            <Link to="/compliance/readiness">
              <Button variant="secondary">View Current Score →</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </PortalShell>
  );
}
